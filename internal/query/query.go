// Package query turns the search box syntax into a parameterized
// ClickHouse WHERE clause.
//
// Syntax:
//
//	failed password            words must all appear in the raw event (case-insensitive)
//	"failed password"          quoted phrase
//	host:web01                 field equals value
//	user.name:adm*             trailing/leading * matches any text
//	-event.outcome:success     leading - negates a term
//
// host, source and message are columns; any other name is looked up in the
// parsed fields map.
package query

import (
	"fmt"
	"strings"
	"time"
)

// Query is a parsed search plus its time range.
type Query struct {
	Terms []Term
	From  time.Time
	To    time.Time
}

// Term is one search condition.
type Term struct {
	Field  string // empty for a free-text term
	Value  string
	Negate bool
}

var columns = map[string]string{"host": "host", "source": "source", "message": "message"}

// Parse splits the search string into terms.
func Parse(s string) (Query, error) {
	var q Query
	toks, err := tokenize(s)
	if err != nil {
		return q, err
	}
	for _, tok := range toks {
		t := Term{}
		if strings.HasPrefix(tok.text, "-") && len(tok.text) > 1 && !tok.quotedStart {
			t.Negate = true
			tok.text = tok.text[1:]
		}
		if field, value, ok := strings.Cut(tok.text, ":"); ok && !tok.quotedStart && validField(field) {
			t.Field, t.Value = field, value
		} else {
			t.Value = tok.text
		}
		if t.Value == "" && t.Field == "" {
			continue
		}
		q.Terms = append(q.Terms, t)
	}
	return q, nil
}

type token struct {
	text        string
	quotedStart bool // the token began with a quote, so ':' and '-' are literal
}

func tokenize(s string) ([]token, error) {
	var (
		toks []token
		cur  strings.Builder
		in   bool
		qs   bool
	)
	flush := func() {
		if cur.Len() > 0 || qs {
			toks = append(toks, token{cur.String(), qs})
		}
		cur.Reset()
		qs = false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			if !in && cur.Len() == 0 {
				qs = true
			}
			in = !in
		case c == '\\' && in && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case (c == ' ' || c == '\t') && !in:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	if in {
		return nil, fmt.Errorf("unclosed quote")
	}
	flush()
	return toks, nil
}

func validField(f string) bool {
	if f == "" || len(f) > 128 {
		return false
	}
	for _, c := range f {
		if !(c == '.' || c == '_' || c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// Where builds the WHERE clause and its positional arguments. Values are
// always bound as parameters, never spliced into the SQL.
func (q Query) Where() (string, []any) {
	clauses := []string{"time >= ?", "time < ?"}
	args := []any{q.From, q.To}
	for _, t := range q.Terms {
		var c string
		switch {
		case t.Field == "":
			c = "positionCaseInsensitive(raw, ?) > 0"
			args = append(args, t.Value)
		default:
			col, ok := columns[t.Field]
			if !ok {
				col = "fields[?]"
				args = append(args, t.Field)
			}
			if strings.Contains(t.Value, "*") {
				c = col + " ILIKE ?"
				args = append(args, likePattern(t.Value))
			} else {
				c = col + " = ?"
				args = append(args, t.Value)
			}
		}
		if t.Negate {
			c = "NOT (" + c + ")"
		}
		clauses = append(clauses, c)
	}
	return strings.Join(clauses, " AND "), args
}

// likePattern escapes LIKE metacharacters and turns * into %.
func likePattern(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`, `*`, `%`)
	return r.Replace(v)
}

// ParseRange accepts a relative range ("15m", "24h", "7d") ending now.
func ParseRange(s string, now time.Time) (from, to time.Time, err error) {
	if s == "" {
		s = "24h"
	}
	unit := s[len(s)-1]
	var n int
	if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &n); err != nil || n <= 0 {
		return from, to, fmt.Errorf("bad range %q", s)
	}
	var d time.Duration
	switch unit {
	case 'm':
		d = time.Duration(n) * time.Minute
	case 'h':
		d = time.Duration(n) * time.Hour
	case 'd':
		d = time.Duration(n) * 24 * time.Hour
	default:
		return from, to, fmt.Errorf("bad range %q: use m, h or d", s)
	}
	return now.Add(-d), now.Add(time.Minute), nil
}
