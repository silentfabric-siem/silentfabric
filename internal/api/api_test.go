package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/query"
	"github.com/silentfabric-siem/silentfabric/internal/store"
)

type fakeBackend struct {
	lastQuery query.Query
	lastLimit int
	lastLevel string
}

func (f *fakeBackend) Search(_ context.Context, q query.Query, limit int) (store.SearchResult, error) {
	f.lastQuery, f.lastLimit = q, limit
	return store.SearchResult{Total: 1, Events: []store.EventRow{{Host: "web01", Message: "hi"}}}, nil
}

func (f *fakeBackend) Alerts(_ context.Context, _, _ time.Time, level string, limit int) ([]store.AlertRow, error) {
	f.lastLevel, f.lastLimit = level, limit
	return nil, nil
}

func do(h http.Handler, path, user, pass string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthRequired(t *testing.T) {
	h := Handler(&fakeBackend{}, "admin", "s3cret")
	for _, path := range []string{"/", "/api/v1/search", "/api/v1/alerts"} {
		if rec := do(h, path, "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without auth: %d", path, rec.Code)
		}
		if rec := do(h, path, "admin", "wrong"); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s wrong password: %d", path, rec.Code)
		}
	}
}

func TestSearch(t *testing.T) {
	b := &fakeBackend{}
	h := Handler(b, "admin", "s3cret")
	rec := do(h, "/api/v1/search?q=host:web01+failed&range=1h&limit=5000", "admin", "s3cret")
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rec.Code, rec.Body)
	}
	var res store.SearchResult
	json.NewDecoder(rec.Body).Decode(&res)
	if res.Total != 1 || res.Events[0].Host != "web01" {
		t.Fatalf("res = %+v", res)
	}
	if len(b.lastQuery.Terms) != 2 || b.lastLimit != maxLimit {
		t.Fatalf("query %+v limit %d", b.lastQuery, b.lastLimit)
	}
	if span := b.lastQuery.To.Sub(b.lastQuery.From); span < time.Hour || span > time.Hour+2*time.Minute {
		t.Fatalf("span = %v", span)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing CSP header")
	}
}

func TestSearchBadInput(t *testing.T) {
	h := Handler(&fakeBackend{}, "admin", "s3cret")
	for _, path := range []string{`/api/v1/search?q=%22unclosed`, "/api/v1/search?range=5y"} {
		if rec := do(h, path, "admin", "s3cret"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
}

func TestAlertsAndUI(t *testing.T) {
	b := &fakeBackend{}
	h := Handler(b, "admin", "s3cret")
	rec := do(h, "/api/v1/alerts?level=high", "admin", "s3cret")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"alerts":[]`) || b.lastLevel != "high" {
		t.Fatalf("code %d body %s level %q", rec.Code, rec.Body, b.lastLevel)
	}
	rec = do(h, "/", "admin", "s3cret")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>SilentFabric</title>") {
		t.Fatalf("index: %d", rec.Code)
	}
}

func TestRequireToken(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	if RequireToken("", ok) == nil {
		t.Fatal("nil handler")
	}
	h := RequireToken("tok", ok)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("with token: %d", rec.Code)
	}
}
