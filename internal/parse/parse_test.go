package parse

import (
	"testing"
	"time"

	"github.com/silentfabric-siem/silentfabric/internal/event"
	"github.com/silentfabric-siem/silentfabric/internal/ingest"
)

var now = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func fromSyslog(t *testing.T, line string) event.Event {
	t.Helper()
	ev := ingest.ParseSyslog(line, now)
	Normalize(&ev)
	return ev
}

func fromJSON(t *testing.T, body string) event.Event {
	t.Helper()
	evs, err := ingest.DecodeJSON([]byte(body), now)
	if err != nil || len(evs) != 1 {
		t.Fatalf("decode: %v (%d events)", err, len(evs))
	}
	Normalize(&evs[0])
	return evs[0]
}

func expect(t *testing.T, ev event.Event, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if ev.Fields[k] != v {
			t.Errorf("%s = %q, want %q", k, ev.Fields[k], v)
		}
	}
}

func TestLinuxSSH(t *testing.T) {
	ev := fromSyslog(t, "<38>Oct 21 11:30:00 web01 sshd[999]: Failed password for invalid user admin from 203.0.113.9 port 50022 ssh2")
	expect(t, ev, map[string]string{
		"event.action": "ssh-login", "event.outcome": "failure", "user.name": "admin",
		"source.ip": "203.0.113.9", "source.port": "50022", "event.dataset": "syslog",
	})

	ev = fromSyslog(t, "<38>Oct 21 11:30:00 web01 sshd[999]: Accepted publickey for matt from 198.51.100.4 port 4022 ssh2: ED25519 SHA256:abc")
	expect(t, ev, map[string]string{"event.outcome": "success", "user.name": "matt", "ssh.method": "publickey"})
}

func TestLinuxSudoAndSu(t *testing.T) {
	ev := fromSyslog(t, "<85>Oct 21 11:31:00 web01 sudo:     matt : TTY=pts/0 ; PWD=/home/matt ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
	expect(t, ev, map[string]string{
		"event.action": "sudo", "user.name": "matt", "user.target.name": "root",
		"process.command_line": "/usr/bin/cat /etc/shadow",
	})

	ev = fromSyslog(t, "<85>Oct 21 11:31:00 web01 sudo:     matt : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/matt ; USER=root ; COMMAND=/bin/bash")
	expect(t, ev, map[string]string{"event.outcome": "failure", "user.name": "matt"})

	ev = fromSyslog(t, "<85>Oct 21 11:31:00 web01 su[123]: FAILED SU (to root) matt on pts/1")
	expect(t, ev, map[string]string{"event.action": "su", "event.outcome": "failure", "user.name": "matt", "user.target.name": "root"})

	ev = fromSyslog(t, "<85>Oct 21 11:31:00 web01 su: FAILED su for root by matt")
	expect(t, ev, map[string]string{"event.outcome": "failure", "user.name": "matt", "user.target.name": "root"})

	ev = fromSyslog(t, "<86>Oct 21 11:32:00 web01 useradd[4242]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash")
	expect(t, ev, map[string]string{"event.action": "user-created", "user.target.name": "backdoor"})
}

func TestJournald(t *testing.T) {
	ev := fromJSON(t, `{"MESSAGE":"Failed password for root from 192.0.2.1 port 22 ssh2","_HOSTNAME":"db01","SYSLOG_IDENTIFIER":"sshd","_PID":"812","__REALTIME_TIMESTAMP":"1792584000000000"}`)
	if ev.Host != "db01" || !ev.Time.Equal(time.UnixMicro(1792584000000000).UTC()) {
		t.Errorf("host %q time %v", ev.Host, ev.Time)
	}
	expect(t, ev, map[string]string{
		"event.dataset": "linux.journald", "os.type": "linux",
		"event.action": "ssh-login", "user.name": "root", "process.pid": "812",
	})
}

func TestMacOS(t *testing.T) {
	ev := fromJSON(t, `{"timestamp":"2026-10-21 08:15:00.123456-0700","eventMessage":"   matt : TTY=ttys000 ; PWD=/Users/matt ; USER=root ; COMMAND=/usr/bin/whoami","processImagePath":"/usr/bin/sudo","processID":4410,"subsystem":"","messageType":"Default","host":{"name":"matts-mbp"}}`)
	if ev.Host != "matts-mbp" || !ev.Time.Equal(time.Date(2026, 10, 21, 15, 15, 0, 123456000, time.UTC)) {
		t.Errorf("host %q time %v", ev.Host, ev.Time)
	}
	expect(t, ev, map[string]string{
		"event.dataset": "macos.unifiedlog", "os.type": "macos", "syslog.appname": "sudo",
		"event.action": "sudo", "user.target.name": "root", "process.pid": "4410",
	})
}

func TestWindowsNXLog(t *testing.T) {
	ev := fromJSON(t, `{"EventTime":"2026-10-21 10:00:00","Hostname":"WS01.corp.local","EventID":4625,"SourceName":"Microsoft-Windows-Security-Auditing","Channel":"Security","TargetUserName":"administrator","IpAddress":"10.0.0.50","IpPort":"0","LogonType":"3","Message":"An account failed to log on."}`)
	if ev.Host != "WS01.corp.local" || ev.Message != "An account failed to log on." {
		t.Errorf("host %q message %q", ev.Host, ev.Message)
	}
	expect(t, ev, map[string]string{
		"EventID": "4625", "Provider_Name": "Microsoft-Windows-Security-Auditing", "Computer": "WS01.corp.local",
		"event.dataset": "windows.security", "event.action": "logon-failed", "event.outcome": "failure",
		"user.name": "administrator", "source.ip": "10.0.0.50", "windows.logon_type": "3", "os.type": "windows",
	})
}

func TestWindowsWinlogbeatSysmon(t *testing.T) {
	ev := fromJSON(t, `{"@timestamp":"2026-10-21T10:00:00Z","message":"Process Create","winlog":{"event_id":1,"channel":"Microsoft-Windows-Sysmon/Operational","provider_name":"Microsoft-Windows-Sysmon","computer_name":"WS02","event_data":{"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell -enc SQBFAFgA","ProcessId":"12345678","User":"CORP\\matt"}}}`)
	expect(t, ev, map[string]string{
		"EventID": "1", "Image": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"CommandLine": "powershell -enc SQBFAFgA", "Computer": "WS02",
		"event.dataset": "windows.sysmon", "event.action": "process-created",
		"process.name": "powershell.exe", "process.pid": "12345678", "user.name": `CORP\matt`,
	})
}

func TestWindowsFluentBit(t *testing.T) {
	ev := fromJSON(t, `{"ProviderName":"Service Control Manager","EventID":7045,"Channel":"System","Computer":"SRV01","Message":"A service was installed in the system."}`)
	expect(t, ev, map[string]string{"event.dataset": "windows.system", "event.action": "service-installed", "Provider_Name": "Service Control Manager"})
	if ev.Host != "SRV01" {
		t.Errorf("host = %q", ev.Host)
	}
}

func TestUniFiIptables(t *testing.T) {
	ev := fromSyslog(t, "<4>Oct 21 11:40:00 UDM-Pro kernel: [WAN_LOCAL-default-D]IN=eth8 OUT= MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 SRC=203.0.113.9 DST=198.51.100.1 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=0 DF PROTO=TCP SPT=51234 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0")
	expect(t, ev, map[string]string{
		"event.dataset": "unifi.firewall", "rule.name": "WAN_LOCAL-default-D", "event.action": "deny",
		"source.ip": "203.0.113.9", "source.port": "51234", "destination.ip": "198.51.100.1",
		"destination.port": "22", "network.transport": "tcp", "observer.ingress.interface": "eth8",
		"observer.vendor": "Ubiquiti",
	})
}

func TestPeerAddressDoesNotMaskParsedSource(t *testing.T) {
	ev := ingest.ParseSyslog("<4>Oct 21 11:40:00 gw kernel: [LAN_IN-2000-A]IN=br0 OUT=eth8 SRC=192.168.1.5 DST=1.1.1.1 PROTO=UDP SPT=5353 DPT=53", now)
	ev.Fields["log.source.ip"] = "192.168.1.1" // set by the listener
	Normalize(&ev)
	expect(t, ev, map[string]string{"source.ip": "192.168.1.5", "event.action": "allow", "event.dataset": "unifi.firewall"})
}

func TestUFW(t *testing.T) {
	ev := fromSyslog(t, "<4>Oct 21 11:41:00 web01 kernel: [12345.678901] [UFW BLOCK] IN=ens3 OUT= MAC=00:00 SRC=192.0.2.44 DST=10.0.0.2 LEN=40 PROTO=TCP SPT=6000 DPT=3389 SYN")
	expect(t, ev, map[string]string{"event.dataset": "linux.iptables", "rule.name": "UFW BLOCK", "event.action": "deny", "destination.port": "3389"})
}

func TestUniFiCEF(t *testing.T) {
	ev := fromSyslog(t, `<14>Oct 21 11:42:00 UDM-Pro CEF:0|Ubiquiti|UniFi Network|9.0.114|544|Admin Accessed UniFi Network|1|UNIFIcategory=System UNIFIsubCategory=Admin UNIFIhost=UDM Pro src=192.168.1.20 suser=matt msg=matt accessed UniFi Network using the web.`)
	expect(t, ev, map[string]string{
		"event.dataset": "unifi.system", "observer.vendor": "Ubiquiti", "event.code": "544",
		"source.ip": "192.168.1.20", "user.name": "matt", "cef.UNIFIhost": "UDM Pro",
		"cef.msg": "matt accessed UniFi Network using the web.",
	})
	if ev.Message != "Admin Accessed UniFi Network" {
		t.Errorf("message = %q", ev.Message)
	}
}

func TestSonicWall(t *testing.T) {
	ev := fromSyslog(t, `<134> id=firewall sn=0017C5A1B2C3 time="2026-10-21 11:43:00 UTC" fw=203.0.113.1 pri=1 c=32 m=36 msg="TCP packet dropped due to Policy" app=49175 n=1234 src=198.51.100.7:44321:X1 dst=10.0.0.10:3389:X0:rdp-host proto=tcp/ms-wbt-server fw_action="drop"`)
	expect(t, ev, map[string]string{
		"event.dataset": "sonicwall.firewall", "observer.serial_number": "0017C5A1B2C3", "event.code": "36",
		"source.ip": "198.51.100.7", "source.port": "44321", "observer.ingress.interface": "X1",
		"destination.ip": "10.0.0.10", "destination.port": "3389", "destination.hostname": "rdp-host",
		"network.transport": "tcp", "network.protocol": "ms-wbt-server", "event.action": "deny", "sonicwall.fw_action": "drop",
		"sonicwall.time": "2026-10-21 11:43:00 UTC",
	})
	if ev.Message != "TCP packet dropped due to Policy" || ev.Host != "203.0.113.1" {
		t.Errorf("message %q host %q", ev.Message, ev.Host)
	}
}

func TestUnknownLeftAlone(t *testing.T) {
	ev := fromSyslog(t, "<14>Oct 21 11:44:00 nas01 smbd[1]: some message")
	if len(ev.Fields) != 5 { // facility, severity, appname, procid, event.dataset
		t.Errorf("fields = %v", ev.Fields)
	}
}

func TestKV(t *testing.T) {
	got := KV(`a=1 flag b="two words" c= d="esc \"q\""`)
	want := map[string]string{"a": "1", "b": "two words", "c": "", "d": `esc "q"`}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["flag"]; ok {
		t.Error("bare token should be skipped")
	}
}
