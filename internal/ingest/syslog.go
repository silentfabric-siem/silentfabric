// Package ingest receives raw logs and turns them into events.
package ingest

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/event"
)

var facilityNames = []string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

var severityNames = []string{
	"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
}

// ParseSyslog parses an RFC 5424 or RFC 3164 message. It never fails: anything
// it cannot parse is kept as the message so no log is dropped.
func ParseSyslog(line string, now time.Time) event.Event {
	line = strings.TrimRight(line, "\r\n\x00")
	ev := event.Event{
		Time:       now,
		ReceivedAt: now,
		Source:     "syslog",
		Message:    line,
		Fields:     map[string]string{},
		Raw:        line,
	}

	rest, ok := parsePriority(line, ev.Fields)
	if !ok {
		return ev
	}
	if strings.HasPrefix(rest, "1 ") {
		parse5424(rest[2:], &ev)
	} else {
		parse3164(rest, now, &ev)
	}
	return ev
}

func parsePriority(line string, fields map[string]string) (string, bool) {
	if !strings.HasPrefix(line, "<") {
		return line, false
	}
	end := strings.IndexByte(line, '>')
	if end < 2 || end > 4 {
		return line, false
	}
	pri, err := strconv.Atoi(line[1:end])
	if err != nil || pri > 191 {
		return line, false
	}
	fields["syslog.facility"] = facilityNames[pri/8]
	fields["syslog.severity"] = severityNames[pri%8]
	return line[end+1:], true
}

// parse5424 handles "TIMESTAMP HOST APP PROCID MSGID [SD] MSG".
func parse5424(s string, ev *event.Event) {
	parts := strings.SplitN(s, " ", 6)
	if len(parts) < 6 {
		ev.Message = s
		return
	}
	if t, err := time.Parse(time.RFC3339Nano, parts[0]); err == nil {
		ev.Time = t
	}
	ev.Host = nilValue(parts[1])
	setIf(ev.Fields, "syslog.appname", nilValue(parts[2]))
	setIf(ev.Fields, "syslog.procid", nilValue(parts[3]))
	setIf(ev.Fields, "syslog.msgid", nilValue(parts[4]))

	msg := parts[5]
	if strings.HasPrefix(msg, "-") {
		msg = strings.TrimPrefix(strings.TrimPrefix(msg, "-"), " ")
	} else if strings.HasPrefix(msg, "[") {
		end := structuredDataEnd(msg)
		ev.Fields["syslog.structured_data"] = msg[:end]
		msg = strings.TrimPrefix(msg[end:], " ")
	}
	ev.Message = strings.TrimPrefix(msg, "\ufeff")
}

// structuredDataEnd finds the end of one or more SD-ELEMENTs, honouring
// escaped "]" inside quoted parameter values.
func structuredDataEnd(s string) int {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			inQuote = !inQuote
		case ']':
			if !inQuote && (i+1 == len(s) || s[i+1] != '[') {
				return i + 1
			}
		}
	}
	return len(s)
}

// parse3164 handles "Mmm dd hh:mm:ss HOST TAG[PID]: MSG".
func parse3164(s string, now time.Time, ev *event.Event) {
	if len(s) >= 16 {
		if t, err := time.ParseInLocation(time.Stamp, s[:15], now.Location()); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			// Logs from late December arriving in January belong to last year.
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			ev.Time = t
			s = s[16:]
		}
	}
	host, rest, found := strings.Cut(s, " ")
	if !found {
		ev.Message = s
		return
	}
	ev.Host = host
	if tag, msg, ok := strings.Cut(rest, ": "); ok && !strings.Contains(tag, " ") {
		if name, pid, ok := strings.Cut(tag, "["); ok {
			setIf(ev.Fields, "syslog.appname", name)
			setIf(ev.Fields, "syslog.procid", strings.TrimSuffix(pid, "]"))
		} else {
			setIf(ev.Fields, "syslog.appname", tag)
		}
		rest = msg
	}
	ev.Message = rest
}

func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func setIf(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}

// ListenSyslogUDP reads syslog datagrams until ctx is cancelled.
func ListenSyslogUDP(ctx context.Context, addr string, out chan<- event.Event) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	slog.Info("syslog listening", "proto", "udp", "addr", conn.LocalAddr().String())

	buf := make([]byte, 64*1024)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ev := ParseSyslog(string(buf[:n]), time.Now().UTC())
		if host, _, err := net.SplitHostPort(peer.String()); err == nil {
			ev.Fields["log.source.ip"] = host
			if ev.Host == "" {
				ev.Host = host
			}
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}
