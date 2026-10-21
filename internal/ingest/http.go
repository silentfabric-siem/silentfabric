package ingest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/event"
)

const maxBodyBytes = 10 << 20

var timeKeys = []string{"@timestamp", "timestamp", "time"}

// DecodeJSON accepts a single JSON object, a JSON array of objects, or
// newline-delimited JSON, and returns one event per object.
func DecodeJSON(body []byte, now time.Time) ([]event.Event, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, nil
	}

	var objects []map[string]interface{}
	if body[0] == '[' {
		if err := json.Unmarshal(body, &objects); err != nil {
			return nil, err
		}
	} else {
		sc := bufio.NewScanner(bytes.NewReader(body))
		sc.Buffer(make([]byte, 0, 64*1024), maxBodyBytes)
		for line := 1; sc.Scan(); line++ {
			b := bytes.TrimSpace(sc.Bytes())
			if len(b) == 0 {
				continue
			}
			var obj map[string]interface{}
			if err := json.Unmarshal(b, &obj); err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			objects = append(objects, obj)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	events := make([]event.Event, 0, len(objects))
	for _, obj := range objects {
		raw, _ := json.Marshal(obj)
		ev := event.Event{
			Time:       now,
			ReceivedAt: now,
			Source:     "http",
			Fields:     event.Flatten(obj),
			Raw:        string(raw),
		}
		for _, k := range timeKeys {
			if t, err := time.Parse(time.RFC3339Nano, ev.Fields[k]); err == nil {
				ev.Time = t
				break
			}
		}
		ev.Message = ev.Fields["message"]
		ev.Host = firstNonEmpty(ev.Fields["host.name"], ev.Fields["host"], ev.Fields["hostname"])
		events = append(events, ev)
	}
	return events, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// HTTPHandler accepts POST /api/v1/events with JSON or NDJSON bodies.
func HTTPHandler(out chan<- event.Event) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		events, err := DecodeJSON(body, time.Now().UTC())
		if err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		for _, ev := range events {
			select {
			case out <- ev:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"accepted":%d}`+"\n", len(events))
	})
}
