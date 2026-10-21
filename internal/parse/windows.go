package parse

import (
	"strings"

	"github.com/silentfabric-siem/silentfabric/internal/event"
)

// windowsActions names well-known Security, System and Sysmon event IDs.
var windowsActions = map[string]map[string]string{
	"security": {
		"1102": "audit-log-cleared",
		"4624": "logged-in",
		"4625": "logon-failed",
		"4634": "logged-out",
		"4648": "explicit-credential-logon",
		"4672": "special-privileges-assigned",
		"4688": "process-created",
		"4697": "service-installed",
		"4698": "scheduled-task-created",
		"4720": "user-created",
		"4722": "user-enabled",
		"4724": "password-reset",
		"4726": "user-deleted",
		"4728": "group-member-added",
		"4732": "group-member-added",
		"4740": "user-locked-out",
		"4756": "group-member-added",
	},
	"system": {
		"7045": "service-installed",
		"104":  "log-cleared",
	},
	"sysmon": {
		"1":  "process-created",
		"3":  "network-connection",
		"7":  "image-loaded",
		"8":  "remote-thread-created",
		"10": "process-accessed",
		"11": "file-created",
		"12": "registry-changed",
		"13": "registry-changed",
		"22": "dns-query",
		"23": "file-deleted",
	},
	"powershell": {
		"4103": "module-logged",
		"4104": "script-block-logged",
	},
}

// windowsFieldMap copies Windows event data into common field names.
var windowsFieldMap = map[string]string{
	"TargetUserName":  "user.name",
	"SubjectUserName": "user.subject.name",
	"User":            "user.name",
	"IpAddress":       "source.ip",
	"IpPort":          "source.port",
	"SourceIp":        "source.ip",
	"SourcePort":      "source.port",
	"DestinationIp":   "destination.ip",
	"DestinationPort": "destination.port",
	"Image":           "process.executable",
	"NewProcessName":  "process.executable",
	"CommandLine":     "process.command_line",
	"ProcessId":       "process.pid",
	"ParentImage":     "process.parent.executable",
	"QueryName":       "dns.question.name",
	"TargetFilename":  "file.path",
	"ServiceName":     "service.name",
	"LogonType":       "windows.logon_type",
}

// parseWindows recognises Windows events from NXLog (EventID + SourceName),
// Fluent Bit winevtlog (EventID + ProviderName) and Winlogbeat/Elastic Agent
// (winlog.event_id). Event data fields are exposed under their native names
// (EventID, Image, CommandLine...) so SigmaHQ Windows rules match unchanged.
func parseWindows(ev *event.Event) bool {
	f := ev.Fields
	switch {
	case f["winlog.event_id"] != "":
		for k, v := range f {
			if name, ok := strings.CutPrefix(k, "winlog.event_data."); ok {
				f[name] = v
			}
		}
		setDefault(f, "EventID", f["winlog.event_id"])
		setDefault(f, "Channel", f["winlog.channel"])
		setDefault(f, "Provider_Name", f["winlog.provider_name"])
		setDefault(f, "Computer", f["winlog.computer_name"])
	case f["EventID"] != "" && (f["SourceName"] != "" || f["ProviderName"] != "" || f["Channel"] != ""):
		setDefault(f, "Provider_Name", f["SourceName"])
		setDefault(f, "Provider_Name", f["ProviderName"])
		setDefault(f, "Computer", f["Hostname"])
	default:
		return false
	}

	if ev.Message == "" {
		ev.Message = f["Message"]
	}
	if ev.Host == "" {
		ev.Host = f["Computer"]
	}
	f["os.type"] = "windows"
	f["event.code"] = f["EventID"]

	group := windowsChannelGroup(f["Channel"])
	f["event.dataset"] = "windows." + group
	if action := windowsActions[group][f["EventID"]]; action != "" {
		f["event.action"] = action
	}
	for src, dst := range windowsFieldMap {
		if v := f[src]; v != "" && v != "-" {
			setDefault(f, dst, v)
		}
	}
	switch f["EventID"] {
	case "4624":
		f["event.outcome"] = "success"
	case "4625":
		f["event.outcome"] = "failure"
	}
	if exe := f["process.executable"]; exe != "" {
		f["process.name"] = exe[strings.LastIndexAny(exe, `\/`)+1:]
	}
	return true
}

func windowsChannelGroup(channel string) string {
	c := strings.ToLower(channel)
	switch {
	case c == "security":
		return "security"
	case c == "system":
		return "system"
	case c == "application":
		return "application"
	case strings.Contains(c, "sysmon"):
		return "sysmon"
	case strings.Contains(c, "powershell"):
		return "powershell"
	case c == "":
		return "unknown"
	default:
		return "other"
	}
}

func setDefault(m map[string]string, k, v string) {
	if v != "" && m[k] == "" {
		m[k] = v
	}
}
