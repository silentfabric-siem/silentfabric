package detect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/event"
)

func TestBundledRulesMatch(t *testing.T) {
	e, err := LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	if e.Len() == 0 {
		t.Fatal("no rules loaded")
	}

	hit := event.Event{
		Time:    time.Now(),
		Host:    "web01",
		Message: "Failed password for root from 203.0.113.9 port 50022 ssh2",
		Fields:  map[string]string{"syslog.appname": "sshd"},
		Raw:     "raw line",
	}
	alerts, err := e.Evaluate(context.Background(), &hit)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].RuleTitle != "Failed SSH Login As Root" || alerts[0].Host != "web01" {
		t.Fatalf("alerts = %+v", alerts)
	}

	miss := hit
	miss.Fields = map[string]string{"syslog.appname": "nginx"}
	alerts, err = e.Evaluate(context.Background(), &miss)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Fatalf("unexpected alerts %+v", alerts)
	}
}

func TestLoadDirReportsBadRules(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.yml"), []byte("title: [unclosed"), 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o644)

	_, err := LoadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "bad.yml") {
		t.Fatalf("err = %v", err)
	}
}
