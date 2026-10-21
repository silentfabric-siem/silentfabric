// Package api serves the search UI and its JSON endpoints.
package api

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/query"
	"github.com/silentfabric-siem/silentfabric/internal/store"
)

//go:embed web
var webFS embed.FS

// Backend is the storage the UI reads from. *store.ClickHouse implements it.
type Backend interface {
	Search(ctx context.Context, q query.Query, limit int) (store.SearchResult, error)
	Alerts(ctx context.Context, from, to time.Time, level string, limit int) ([]store.AlertRow, error)
}

const (
	defaultLimit = 200
	maxLimit     = 1000
)

// Handler returns the UI and query API, protected by HTTP basic auth.
func Handler(b Backend, user, password string) http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/v1/search", func(w http.ResponseWriter, r *http.Request) {
		q, err := query.Parse(r.URL.Query().Get("q"))
		if err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		if q.From, q.To, err = query.ParseRange(r.URL.Query().Get("range"), time.Now().UTC()); err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := b.Search(r.Context(), q, limitParam(r))
		if err != nil {
			slog.Error("search failed", "err", err)
			httpError(w, http.StatusInternalServerError, "search failed")
			return
		}
		writeJSON(w, res)
	})
	mux.HandleFunc("GET /api/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		from, to, err := query.ParseRange(r.URL.Query().Get("range"), time.Now().UTC())
		if err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		alerts, err := b.Alerts(r.Context(), from, to, r.URL.Query().Get("level"), limitParam(r))
		if err != nil {
			slog.Error("alerts query failed", "err", err)
			httpError(w, http.StatusInternalServerError, "alerts query failed")
			return
		}
		if alerts == nil {
			alerts = []store.AlertRow{}
		}
		writeJSON(w, map[string]any{"alerts": alerts})
	})
	return BasicAuth(user, password, securityHeaders(mux))
}

// BasicAuth rejects requests without the configured credentials.
func BasicAuth(user, password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(u), []byte(user)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(p), []byte(password)) == 1
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="SilentFabric", charset="UTF-8"`)
			httpError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireToken guards ingest with a bearer token when one is configured.
func RequireToken(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			httpError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func limitParam(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return defaultLimit
	}
	return min(n, maxLimit)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": strings.TrimSpace(msg)})
}
