package ingest

import (
	"testing"
	"time"
)

var now = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func TestParseSyslog5424(t *testing.T) {
	ev := ParseSyslog(`<34>1 2026-10-21T11:59:58.123Z web01 sshd 4242 ID47 [exampleSDID@32473 iut="3" eventSource="App\]"] Failed password for root`, now)

	if ev.Host != "web01" {
		t.Errorf("host = %q", ev.Host)
	}
	if ev.Message != "Failed password for root" {
		t.Errorf("message = %q", ev.Message)
	}
	if !ev.Time.Equal(time.Date(2026, 10, 21, 11, 59, 58, 123e6, time.UTC)) {
		t.Errorf("time = %v", ev.Time)
	}
	want := map[string]string{
		"syslog.facility": "auth",
		"syslog.severity": "crit",
		"syslog.appname":  "sshd",
		"syslog.procid":   "4242",
		"syslog.msgid":    "ID47",
	}
	for k, v := range want {
		if ev.Fields[k] != v {
			t.Errorf("%s = %q, want %q", k, ev.Fields[k], v)
		}
	}
}

func TestParseSyslog5424NilStructuredData(t *testing.T) {
	ev := ParseSyslog("<13>1 - - - - - - hello", now)
	if ev.Message != "hello" || ev.Host != "" {
		t.Errorf("got host %q message %q", ev.Host, ev.Message)
	}
	if !ev.Time.Equal(now) {
		t.Errorf("time should fall back to receive time, got %v", ev.Time)
	}
}

func TestParseSyslog3164(t *testing.T) {
	ev := ParseSyslog("<38>Oct 21 11:30:00 fw01 sshd[999]: Accepted publickey for matt", now)

	if ev.Host != "fw01" || ev.Message != "Accepted publickey for matt" {
		t.Errorf("got host %q message %q", ev.Host, ev.Message)
	}
	if ev.Fields["syslog.appname"] != "sshd" || ev.Fields["syslog.procid"] != "999" {
		t.Errorf("fields = %v", ev.Fields)
	}
	if !ev.Time.Equal(time.Date(2026, 10, 21, 11, 30, 0, 0, time.UTC)) {
		t.Errorf("time = %v", ev.Time)
	}
}

func TestParseSyslog3164YearRollover(t *testing.T) {
	jan := time.Date(2027, 1, 1, 0, 5, 0, 0, time.UTC)
	ev := ParseSyslog("<14>Dec 31 23:59:00 host app: late", jan)
	if ev.Time.Year() != 2026 {
		t.Errorf("year = %d, want 2026", ev.Time.Year())
	}
}

func TestParseSyslogGarbageIsKept(t *testing.T) {
	ev := ParseSyslog("not syslog at all", now)
	if ev.Message != "not syslog at all" || ev.Raw != "not syslog at all" {
		t.Errorf("message = %q", ev.Message)
	}
}
