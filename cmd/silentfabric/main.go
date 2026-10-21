// Command silentfabric runs the SIEM server and its rule tooling.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/api"
	"github.com/silentfabric-siem/silentfabric/internal/config"
	"github.com/silentfabric-siem/silentfabric/internal/detect"
	"github.com/silentfabric-siem/silentfabric/internal/event"
	"github.com/silentfabric-siem/silentfabric/internal/ingest"
	"github.com/silentfabric-siem/silentfabric/internal/parse"
	"github.com/silentfabric-siem/silentfabric/internal/pipeline"
	"github.com/silentfabric-siem/silentfabric/internal/store"
)

const usage = `usage:
  silentfabric serve [-config file]       run ingest, detection and storage
  silentfabric rules check <dir>          parse every Sigma rule in dir
  silentfabric rules test <dir> <file>    run rules against JSON/NDJSON events
`

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("missing command")
	}
	switch {
	case args[0] == "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		cfgPath := fs.String("config", "", "path to YAML config")
		fs.Parse(args[1:])
		return serve(*cfgPath)
	case len(args) == 3 && args[0] == "rules" && args[1] == "check":
		e, err := detect.LoadDir(args[2])
		if err != nil {
			return err
		}
		fmt.Printf("ok: %d rule(s)\n", e.Len())
		return nil
	case len(args) == 4 && args[0] == "rules" && args[1] == "test":
		return rulesTest(args[2], args[3])
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func rulesTest(dir, file string) error {
	e, err := detect.LoadDir(dir)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	evs, err := ingest.DecodeJSON(b, time.Now().UTC())
	if err != nil {
		return err
	}
	hits := 0
	for i := range evs {
		parse.Normalize(&evs[i])
		alerts, err := e.Evaluate(context.Background(), &evs[i])
		if err != nil {
			return err
		}
		for _, a := range alerts {
			hits++
			fmt.Printf("event %d matched %q (%s)\n", i+1, a.RuleTitle, a.Level)
		}
	}
	fmt.Printf("%d event(s), %d match(es)\n", len(evs), hits)
	return nil
}

func serve(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	engine, err := detect.LoadDir(cfg.RulesDir)
	if err != nil {
		return err
	}
	slog.Info("rules loaded", "count", engine.Len(), "dir", cfg.RulesDir)

	ch, err := store.OpenClickHouse(ctx, cfg.ClickHouseDSN)
	if err != nil {
		return err
	}
	defer ch.Close()

	events := make(chan event.Event, 10000)

	go func() {
		if err := ingest.ListenSyslogUDP(ctx, cfg.SyslogUDP, events); err != nil {
			slog.Error("syslog udp listener stopped", "err", err)
			stop()
		}
	}()
	if cfg.SyslogTCP != "" {
		go func() {
			if err := ingest.ListenSyslogTCP(ctx, cfg.SyslogTCP, events); err != nil {
				slog.Error("syslog tcp listener stopped", "err", err)
				stop()
			}
		}()
	}

	mux := http.NewServeMux()
	mux.Handle("/api/v1/events", api.RequireToken(cfg.IngestToken, ingest.HTTPHandler(events)))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	if cfg.UIPassword != "" {
		mux.Handle("/", api.Handler(ch, cfg.UIUser, cfg.UIPassword))
	} else {
		slog.Warn("search UI disabled: set SF_UI_PASSWORD to enable it")
	}
	if cfg.IngestToken == "" {
		slog.Warn("HTTP ingest accepts unauthenticated events: set SF_INGEST_TOKEN to require a token")
	}
	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		slog.Info("http listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server stopped", "err", err)
			stop()
		}
	}()

	done := make(chan struct{})
	go func() {
		pipeline.Run(ctx, events, engine, ch, pipeline.Options{
			BatchSize:     cfg.BatchSize,
			FlushInterval: cfg.FlushInterval,
			OnAlert:       notifier(cfg.AlertWebhook),
		})
		close(done)
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
	<-done
	return nil
}

// notifier logs every alert and, if a webhook URL is set, posts it as JSON.
func notifier(webhook string) func(detect.Alert) {
	client := &http.Client{Timeout: 5 * time.Second}
	return func(a detect.Alert) {
		slog.Warn("alert", "rule", a.RuleTitle, "level", a.Level, "host", a.Host)
		if webhook == "" {
			return
		}
		body, _ := json.Marshal(map[string]interface{}{
			"time": a.Time, "rule_id": a.RuleID, "rule": a.RuleTitle,
			"level": a.Level, "host": a.Host, "tags": a.Tags,
		})
		go func() {
			resp, err := client.Post(webhook, "application/json", bytes.NewReader(body))
			if err != nil {
				slog.Error("webhook failed", "err", err)
				return
			}
			resp.Body.Close()
		}()
	}
}
