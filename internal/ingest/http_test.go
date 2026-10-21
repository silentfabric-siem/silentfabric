package ingest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/event"
)

func TestDecodeJSONForms(t *testing.T) {
	cases := map[string]string{
		"object": `{"message":"a","host":{"name":"h1"}}`,
		"array":  `[{"message":"a","host":{"name":"h1"}}]`,
		"ndjson": "{\"message\":\"a\",\"host\":{\"name\":\"h1\"}}\n\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			evs, err := DecodeJSON([]byte(body), now)
			if err != nil {
				t.Fatal(err)
			}
			if len(evs) != 1 || evs[0].Message != "a" || evs[0].Host != "h1" {
				t.Fatalf("got %+v", evs)
			}
		})
	}
}

func TestDecodeJSONTimestampAndNesting(t *testing.T) {
	evs, err := DecodeJSON([]byte(`{"@timestamp":"2026-10-20T08:00:00Z","process":{"name":"bash","args":["-c","id"]},"pid":42}`), now)
	if err != nil {
		t.Fatal(err)
	}
	ev := evs[0]
	if !ev.Time.Equal(time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("time = %v", ev.Time)
	}
	if ev.Fields["process.name"] != "bash" || ev.Fields["process.args.1"] != "id" || ev.Fields["pid"] != "42" {
		t.Errorf("fields = %v", ev.Fields)
	}
}

func TestDecodeJSONBadLine(t *testing.T) {
	if _, err := DecodeJSON([]byte("{\"a\":1}\nnope"), now); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("err = %v", err)
	}
}

func TestHTTPHandler(t *testing.T) {
	out := make(chan event.Event, 2)
	h := HTTPHandler(out)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(`[{"message":"x"},{"message":"y"}]`)))
	if rec.Code != http.StatusAccepted || len(out) != 2 {
		t.Fatalf("code %d, queued %d, body %s", rec.Code, len(out), rec.Body)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code = %d", rec.Code)
	}
}
