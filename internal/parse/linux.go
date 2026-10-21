package parse

import (
	"path"
	"regexp"
	"strconv"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/event"
)

// parseJournald recognises systemd-journald JSON as exported by
// `journalctl -o json`, Fluent Bit's systemd input or Vector.
func parseJournald(ev *event.Event) bool {
	f := ev.Fields
	if f["MESSAGE"] == "" || (f["_HOSTNAME"] == "" && f["SYSLOG_IDENTIFIER"] == "" && f["_SYSTEMD_UNIT"] == "") {
		return false
	}
	ev.Message = f["MESSAGE"]
	if ev.Host == "" {
		ev.Host = f["_HOSTNAME"]
	}
	app := f["SYSLOG_IDENTIFIER"]
	if app == "" {
		app = path.Base(f["_EXE"])
	}
	setDefault(f, "syslog.appname", app)
	setDefault(f, "process.pid", f["_PID"])
	setDefault(f, "process.executable", f["_EXE"])
	setDefault(f, "systemd.unit", f["_SYSTEMD_UNIT"])
	if us, err := strconv.ParseInt(f["__REALTIME_TIMESTAMP"], 10, 64); err == nil {
		ev.Time = time.UnixMicro(us).UTC()
	}
	f["os.type"] = "linux"
	f["event.dataset"] = "linux.journald"
	return true
}

// parseMacOS recognises `log stream --style ndjson` output from the macOS
// unified log.
func parseMacOS(ev *event.Event) bool {
	f := ev.Fields
	if f["eventMessage"] == "" || f["processImagePath"] == "" {
		return false
	}
	ev.Message = f["eventMessage"]
	setDefault(f, "syslog.appname", path.Base(f["processImagePath"]))
	setDefault(f, "process.executable", f["processImagePath"])
	setDefault(f, "process.name", path.Base(f["processImagePath"]))
	setDefault(f, "process.pid", f["processID"])
	if t, err := time.Parse("2006-01-02 15:04:05.000000-0700", f["timestamp"]); err == nil {
		ev.Time = t.UTC()
	}
	f["os.type"] = "macos"
	f["event.dataset"] = "macos.unifiedlog"
	return true
}

var (
	sshAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	sshFailed   = regexp.MustCompile(`^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	sshInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)(?: port (\d+))?`)
	sudoCommand = regexp.MustCompile(`^\s*(\S+) : (?:.*?; )?TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.*)$`)
	sudoFailure = regexp.MustCompile(`^\s*(\S+) : (?:\d+ incorrect password attempts?|.*authentication failure)`)
	suSuccess   = regexp.MustCompile(`^\(to (\S+)\) (\S+) on`)
	suFailure   = regexp.MustCompile(`^FAILED (?:su|SU) (?:for (\S+) by (\S+)|\(to (\S+)\) (\S+) on)`)
	userAdd     = regexp.MustCompile(`^new user: name=([^,]+)`)
	userDel     = regexp.MustCompile(`^delete user '([^']+)'`)
)

// parseAuthApps extracts fields from sshd, sudo, su and user-management
// messages. It runs on syslog, journald and macOS events alike.
func parseAuthApps(ev *event.Event) {
	f := ev.Fields
	msg := ev.Message
	switch f["syslog.appname"] {
	case "sshd", "sshd-session":
		if m := sshAccepted.FindStringSubmatch(msg); m != nil {
			setAuth(f, "ssh-login", "success", m[2], m[3], m[4])
			f["ssh.method"] = m[1]
		} else if m := sshFailed.FindStringSubmatch(msg); m != nil {
			setAuth(f, "ssh-login", "failure", m[2], m[3], m[4])
			f["ssh.method"] = m[1]
		} else if m := sshInvalid.FindStringSubmatch(msg); m != nil {
			setAuth(f, "ssh-invalid-user", "failure", m[1], m[2], m[3])
		}
	case "sudo":
		// Failures also carry TTY/USER/COMMAND, so check them first.
		if m := sudoFailure.FindStringSubmatch(msg); m != nil {
			f["event.action"] = "sudo"
			f["event.outcome"] = "failure"
			f["user.name"] = m[1]
		} else if m := sudoCommand.FindStringSubmatch(msg); m != nil {
			f["event.action"] = "sudo"
			f["event.outcome"] = "success"
			f["user.name"] = m[1]
			f["user.target.name"] = m[2]
			f["process.command_line"] = m[3]
		}
	case "su":
		if m := suSuccess.FindStringSubmatch(msg); m != nil {
			f["event.action"] = "su"
			f["event.outcome"] = "success"
			f["user.target.name"] = m[1]
			f["user.name"] = m[2]
		} else if m := suFailure.FindStringSubmatch(msg); m != nil {
			f["event.action"] = "su"
			f["event.outcome"] = "failure"
			// Two message styles: "for TARGET by USER" and "(to TARGET) USER on".
			f["user.target.name"] = m[1] + m[3]
			f["user.name"] = m[2] + m[4]
		}
	case "useradd":
		if m := userAdd.FindStringSubmatch(msg); m != nil {
			f["event.action"] = "user-created"
			f["user.target.name"] = m[1]
		}
	case "userdel":
		if m := userDel.FindStringSubmatch(msg); m != nil {
			f["event.action"] = "user-deleted"
			f["user.target.name"] = m[1]
		}
	}
}

func setAuth(f map[string]string, action, outcome, user, ip, port string) {
	f["event.action"] = action
	f["event.outcome"] = outcome
	f["user.name"] = user
	f["source.ip"] = ip
	if port != "" {
		f["source.port"] = port
	}
}
