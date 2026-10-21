package store

import (
	"context"
	"fmt"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/query"
)

// EventRow is one stored event returned by a search.
type EventRow struct {
	Time    time.Time         `json:"time"`
	Host    string            `json:"host"`
	Source  string            `json:"source"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields"`
	Raw     string            `json:"raw"`
}

// Bucket is one bar of the event histogram.
type Bucket struct {
	Time  time.Time `json:"time"`
	Count uint64    `json:"count"`
}

// ValueCount is one entry of a facet.
type ValueCount struct {
	Value string `json:"value"`
	Count uint64 `json:"count"`
}

// SearchResult is everything the search page shows for one query.
type SearchResult struct {
	From      time.Time               `json:"from"`
	To        time.Time               `json:"to"`
	Step      int64                   `json:"step_seconds"`
	Total     uint64                  `json:"total"`
	Events    []EventRow              `json:"events"`
	Histogram []Bucket                `json:"histogram"`
	Facets    map[string][]ValueCount `json:"facets"`
}

// AlertRow is one stored alert.
type AlertRow struct {
	Time      time.Time `json:"time"`
	RuleID    string    `json:"rule_id"`
	RuleTitle string    `json:"rule_title"`
	Level     string    `json:"level"`
	Tags      []string  `json:"tags"`
	Host      string    `json:"host"`
	EventRaw  string    `json:"event_raw"`
}

// FacetFields are the fields summarized beside search results.
var FacetFields = []string{"host", "event.dataset", "event.action", "event.outcome"}

// Search runs q and returns matching events (newest first), a histogram of
// the whole range and the top values of FacetFields.
func (c *ClickHouse) Search(ctx context.Context, q query.Query, limit int) (SearchResult, error) {
	where, args := q.Where()
	res := SearchResult{
		From: q.From, To: q.To, Step: bucketSeconds(q.To.Sub(q.From)),
		Events: []EventRow{}, Histogram: []Bucket{}, Facets: map[string][]ValueCount{},
	}

	if err := c.conn.QueryRow(ctx, "SELECT count() FROM events WHERE "+where, args...).Scan(&res.Total); err != nil {
		return res, fmt.Errorf("count: %w", err)
	}

	rows, err := c.conn.Query(ctx,
		"SELECT time, host, source, message, fields, raw FROM events WHERE "+where+" ORDER BY time DESC LIMIT ?",
		append(args, limit)...)
	if err != nil {
		return res, fmt.Errorf("events: %w", err)
	}
	for rows.Next() {
		var r EventRow
		if err := rows.Scan(&r.Time, &r.Host, &r.Source, &r.Message, &r.Fields, &r.Raw); err != nil {
			rows.Close()
			return res, err
		}
		res.Events = append(res.Events, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}

	rows, err = c.conn.Query(ctx,
		"SELECT toStartOfInterval(time, toIntervalSecond(?)) AS t, count() FROM events WHERE "+where+" GROUP BY t ORDER BY t",
		append([]any{res.Step}, args...)...)
	if err != nil {
		return res, fmt.Errorf("histogram: %w", err)
	}
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.Time, &b.Count); err != nil {
			rows.Close()
			return res, err
		}
		res.Histogram = append(res.Histogram, b)
	}
	rows.Close()

	for _, field := range FacetFields {
		expr, fargs := "fields[?]", []any{field}
		if field == "host" {
			expr, fargs = "host", nil
		}
		rows, err := c.conn.Query(ctx,
			"SELECT "+expr+" AS v, count() AS n FROM events WHERE "+where+" GROUP BY v HAVING v != '' ORDER BY n DESC LIMIT 8",
			append(fargs, args...)...)
		if err != nil {
			return res, fmt.Errorf("facet %s: %w", field, err)
		}
		for rows.Next() {
			var vc ValueCount
			if err := rows.Scan(&vc.Value, &vc.Count); err != nil {
				rows.Close()
				return res, err
			}
			res.Facets[field] = append(res.Facets[field], vc)
		}
		rows.Close()
	}
	return res, nil
}

// bucketSeconds picks a histogram step that gives roughly 60 bars.
func bucketSeconds(span time.Duration) int64 {
	for _, s := range []int64{60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400} {
		if span/time.Duration(s*int64(time.Second)) <= 60 {
			return s
		}
	}
	return 86400
}

// Alerts returns alerts in [from, to), newest first, optionally limited to
// one severity level.
func (c *ClickHouse) Alerts(ctx context.Context, from, to time.Time, level string, limit int) ([]AlertRow, error) {
	sql := "SELECT time, rule_id, rule_title, level, tags, host, event_raw FROM alerts WHERE time >= ? AND time < ?"
	args := []any{from, to}
	if level != "" {
		sql += " AND level = ?"
		args = append(args, level)
	}
	sql += " ORDER BY time DESC LIMIT ?"
	args = append(args, limit)

	rows, err := c.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRow
	for rows.Next() {
		var a AlertRow
		if err := rows.Scan(&a.Time, &a.RuleID, &a.RuleTitle, &a.Level, &a.Tags, &a.Host, &a.EventRaw); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
