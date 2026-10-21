// Package parse enriches events with normalized fields for known log
// formats: Windows event logs, Linux and macOS system logs, and firewalls.
//
// Common fields follow ECS-style dotted names (source.ip, user.name,
// event.action, event.outcome, event.dataset). Windows events also keep
// their native names (EventID, Image, CommandLine) so SigmaHQ rules match.
package parse

import (
	"github.com/silentfabric-siem/silentfabric/internal/event"
)

// Normalize detects the event's format and adds parsed fields in place.
// Unknown formats are left untouched.
func Normalize(ev *event.Event) {
	if ev.Fields == nil {
		ev.Fields = map[string]string{}
	}

	// Structured agent formats first: they may set Message and the app name
	// that the content parsers below rely on.
	switch {
	case parseWindows(ev):
		return
	case parseJournald(ev), parseMacOS(ev):
	}

	switch {
	case parseCEF(ev, ev.Message):
	case parseSonicWall(ev):
	case parseIptables(ev):
	default:
		parseAuthApps(ev)
	}

	if ev.Fields["event.dataset"] == "" && ev.Source == "syslog" {
		ev.Fields["event.dataset"] = "syslog"
	}
}
