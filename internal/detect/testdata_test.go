package detect

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/ingest"
	"github.com/silentfabric-siem/silentfabric/internal/parse"
)

// TestSampleEventsAgainstBundledRules keeps rules/ and testdata/ in step:
// each sample event should trigger exactly the rules listed here.
func TestSampleEventsAgainstBundledRules(t *testing.T) {
	e, err := LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../testdata/events.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	evs, err := ingest.DecodeJSON(b, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Failed SSH Login As Root",
		"",
		"Windows Security Audit Log Cleared",
		"PowerShell Encoded Command",
		"New Windows Service Installed",
		"Local User Account Created",
		"Failed Sudo Authentication",
		"",
	}
	if len(evs) != len(want) {
		t.Fatalf("%d sample events, want %d", len(evs), len(want))
	}
	for i := range evs {
		parse.Normalize(&evs[i])
		alerts, err := e.Evaluate(context.Background(), &evs[i])
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if len(alerts) > 1 {
			t.Errorf("event %d: %d alerts, want at most 1", i+1, len(alerts))
		}
		if len(alerts) == 1 {
			got = alerts[0].RuleTitle
		}
		if got != want[i] {
			t.Errorf("event %d matched %q, want %q", i+1, got, want[i])
		}
	}
}
