package ingest

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/event"
)

func TestSyslogTCPFraming(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Grab a free port, then hand it to the listener.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()

	out := make(chan event.Event, 10)
	go ListenSyslogTCP(ctx, addr, out)

	var conn net.Conn
	for i := 0; i < 50; i++ {
		if conn, err = net.Dial("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	msg := "<13>1 2026-10-21T10:00:00Z h1 app - - - octet counted"
	conn.Write([]byte("<13>Oct 21 10:00:00 h2 app: newline one\n"))
	conn.Write([]byte(strconv.Itoa(len(msg)) + " " + msg))
	conn.Write([]byte("<13>Oct 21 10:00:00 h3 app: last without newline"))
	conn.Close()

	want := []string{"newline one", "octet counted", "last without newline"}
	for _, w := range want {
		select {
		case ev := <-out:
			if ev.Message != w || ev.Fields["log.source.ip"] != "127.0.0.1" {
				t.Errorf("got message %q source %q, want %q", ev.Message, ev.Fields["log.source.ip"], w)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %q", w)
		}
	}
}
