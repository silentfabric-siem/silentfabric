package parse

import (
	"regexp"
	"strings"

	"github.com/silentfabric-siem/silentfabric/internal/event"
)

// iptablesPrefix matches the log prefix before "IN=", e.g.
// "[WAN_LOCAL-default-D]" on UniFi gateways or "[UFW BLOCK]" on Ubuntu.
var iptablesPrefix = regexp.MustCompile(`\[([^\[\]]+)\]\s*IN=`)

// unifiRule matches UniFi firewall rule names such as WAN_LOCAL-default-D,
// LAN_IN-2000-A or the zone-based "PREROUTING-..." style.
var unifiRule = regexp.MustCompile(`^(?:[A-Z]+_[A-Z]+|[A-Z_]+)-(?:default|\d+)-[ADR]$`)

// parseIptables handles netfilter log lines from UniFi gateways and Linux
// hosts (iptables LOG target, UFW, firewalld).
func parseIptables(ev *event.Event) bool {
	msg := ev.Message
	in := strings.Index(msg, "IN=")
	if in < 0 || !strings.Contains(msg, " SRC=") || !strings.Contains(msg, " PROTO=") {
		return false
	}
	kv := KV(msg[in:])
	f := ev.Fields
	setDefault(f, "observer.ingress.interface", kv["IN"])
	setDefault(f, "observer.egress.interface", kv["OUT"])
	setDefault(f, "source.ip", kv["SRC"])
	setDefault(f, "destination.ip", kv["DST"])
	setDefault(f, "source.port", kv["SPT"])
	setDefault(f, "destination.port", kv["DPT"])
	setDefault(f, "source.mac", kv["MAC"])
	setDefault(f, "network.transport", strings.ToLower(kv["PROTO"]))

	rule := ""
	if m := iptablesPrefix.FindStringSubmatch(msg); m != nil {
		rule = strings.TrimSpace(m[1])
		f["rule.name"] = rule
	}
	upper := strings.ToUpper(rule)
	switch {
	case strings.HasSuffix(rule, "-D"), strings.Contains(upper, "BLOCK"), strings.Contains(upper, "DROP"), strings.Contains(upper, "DENY"):
		f["event.action"] = "deny"
	case strings.HasSuffix(rule, "-R"), strings.Contains(upper, "REJECT"):
		f["event.action"] = "reject"
	case strings.HasSuffix(rule, "-A"), strings.Contains(upper, "ALLOW"), strings.Contains(upper, "ACCEPT"):
		f["event.action"] = "allow"
	}

	if unifiRule.MatchString(rule) {
		f["event.dataset"] = "unifi.firewall"
		f["observer.vendor"] = "Ubiquiti"
	} else {
		f["event.dataset"] = "linux.iptables"
	}
	return true
}

// parseSonicWall handles SonicOS key=value syslog, e.g.
// id=firewall sn=0017C5... time="2026-10-21 10:00:00" fw=203.0.113.1 pri=1 c=32 m=36 msg="..." src=10.0.0.5:51234:X0 dst=8.8.8.8:53:X1 proto=udp/dns
func parseSonicWall(ev *event.Event) bool {
	msg := ev.Message
	if !strings.Contains(msg, "id=firewall") && !(strings.Contains(msg, "sn=") && strings.Contains(msg, " fw=")) {
		return false
	}
	start := strings.Index(msg, "id=")
	if start < 0 {
		start = strings.Index(msg, "sn=")
	}
	kv := KV(msg[start:])
	f := ev.Fields
	for k, v := range kv {
		f["sonicwall."+k] = v
	}
	f["observer.vendor"] = "SonicWall"
	f["observer.product"] = "SonicOS"
	f["event.dataset"] = "sonicwall.firewall"
	setDefault(f, "observer.serial_number", kv["sn"])
	setDefault(f, "observer.ip", kv["fw"])
	setDefault(f, "event.code", kv["m"])
	setDefault(f, "user.name", kv["usr"])
	setDefault(f, "rule.name", kv["rule"])
	setDefault(f, "event.action", kv["fw_action"])

	if ip, port, iface, host := sonicwallEndpoint(kv["src"]); ip != "" {
		f["source.ip"], f["source.port"] = ip, port
		setDefault(f, "observer.ingress.interface", iface)
		setDefault(f, "source.hostname", host)
	}
	if ip, port, iface, host := sonicwallEndpoint(kv["dst"]); ip != "" {
		f["destination.ip"], f["destination.port"] = ip, port
		setDefault(f, "observer.egress.interface", iface)
		setDefault(f, "destination.hostname", host)
	}
	if transport, proto, ok := strings.Cut(kv["proto"], "/"); ok {
		f["network.transport"] = transport
		f["network.protocol"] = proto
	} else if kv["proto"] != "" {
		f["network.transport"] = kv["proto"]
	}
	if kv["msg"] != "" {
		ev.Message = kv["msg"]
	}
	if ev.Host == "" {
		ev.Host = kv["fw"]
	}
	return true
}

// sonicwallEndpoint splits "ip:port:interface[:hostname]".
func sonicwallEndpoint(s string) (ip, port, iface, host string) {
	parts := strings.SplitN(s, ":", 4)
	if len(parts) < 2 || strings.Count(s, ":") > 3 {
		// IPv6 or unexpected form: keep the whole value as the address.
		return s, "", "", ""
	}
	ip, port = parts[0], parts[1]
	if len(parts) > 2 {
		iface = parts[2]
	}
	if len(parts) > 3 {
		host = parts[3]
	}
	return ip, port, iface, host
}
