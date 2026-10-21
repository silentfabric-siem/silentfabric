// Package event defines the normalized event that flows through SilentFabric.
package event

import (
	"fmt"
	"sort"
	"strconv"
	"time"
)

// Event is a single log record after parsing. Fields holds source-specific
// structured data, flattened to dotted keys (for example "process.name").
type Event struct {
	Time       time.Time
	ReceivedAt time.Time
	Source     string // ingest path, e.g. "syslog" or "http"
	Host       string
	Message    string
	Fields     map[string]string
	Raw        string
}

// SigmaView returns the event as a flat map for rule evaluation. Top-level
// attributes are exposed alongside Fields so rules can match on either.
func (e *Event) SigmaView() map[string]interface{} {
	m := make(map[string]interface{}, len(e.Fields)+3)
	for k, v := range e.Fields {
		m[k] = v
	}
	m["message"] = e.Message
	m["host"] = e.Host
	m["source"] = e.Source
	return m
}

// Flatten converts nested JSON-like data into dotted string keys.
func Flatten(in map[string]interface{}) map[string]string {
	out := make(map[string]string, len(in))
	flattenInto(out, "", in)
	return out
}

func flattenInto(out map[string]string, prefix string, v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenInto(out, key, t[k])
		}
	case []interface{}:
		for i, item := range t {
			flattenInto(out, fmt.Sprintf("%s.%d", prefix, i), item)
		}
	case nil:
		out[prefix] = ""
	case string:
		out[prefix] = t
	case float64:
		// 'f' keeps large integers such as PIDs out of exponent form.
		out[prefix] = strconv.FormatFloat(t, 'f', -1, 64)
	default:
		out[prefix] = fmt.Sprint(t)
	}
}
