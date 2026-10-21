package parse

import (
	"strings"

	"github.com/silentfabric-siem/silentfabric/internal/event"
)

// cefExtensionMap maps common CEF extension keys to SilentFabric field names.
var cefExtensionMap = map[string]string{
	"src":                     "source.ip",
	"spt":                     "source.port",
	"dst":                     "destination.ip",
	"dpt":                     "destination.port",
	"proto":                   "network.transport",
	"suser":                   "user.name",
	"duser":                   "user.target.name",
	"shost":                   "source.hostname",
	"dhost":                   "destination.hostname",
	"smac":                    "source.mac",
	"dmac":                    "destination.mac",
	"act":                     "event.action",
	"app":                     "network.protocol",
	"request":                 "url.original",
	"deviceInboundInterface":  "observer.ingress.interface",
	"deviceOutboundInterface": "observer.egress.interface",
}

// parseCEF handles "CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension".
func parseCEF(ev *event.Event, s string) bool {
	idx := strings.Index(s, "CEF:")
	if idx < 0 {
		return false
	}
	header, ext := splitCEFHeader(s[idx+4:])
	if len(header) < 7 {
		return false
	}
	f := ev.Fields
	f["cef.version"] = header[0]
	f["observer.vendor"] = header[1]
	f["observer.product"] = header[2]
	f["observer.version"] = header[3]
	f["event.code"] = header[4]
	f["rule.name"] = header[5]
	f["event.severity"] = header[6]
	ev.Message = header[5]

	for k, v := range cefExtension(ext) {
		f["cef."+k] = v
		if mapped, ok := cefExtensionMap[k]; ok {
			f[mapped] = v
		}
	}
	if t := f["network.transport"]; t != "" {
		f["network.transport"] = strings.ToLower(t)
	}

	vendor := strings.ToLower(header[1])
	switch {
	case strings.Contains(vendor, "ubiquiti"):
		cat := strings.ToLower(strings.ReplaceAll(f["cef.UNIFIcategory"], " ", "_"))
		if cat == "" {
			cat = "cef"
		}
		f["event.dataset"] = "unifi." + cat
	case strings.Contains(vendor, "sonicwall"):
		f["event.dataset"] = "sonicwall.cef"
	default:
		f["event.dataset"] = "cef"
	}
	return true
}

// splitCEFHeader splits the seven pipe-delimited header fields, honouring
// "\|" escapes, and returns the remaining extension string.
func splitCEFHeader(s string) ([]string, string) {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '\\') {
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if c == '|' {
			parts = append(parts, cur.String())
			cur.Reset()
			if len(parts) == 7 {
				return parts, s[i+1:]
			}
			continue
		}
		cur.WriteByte(c)
	}
	parts = append(parts, cur.String())
	return parts, ""
}

// cefExtension parses "k1=v1 with spaces k2=v2". A value runs until the
// next unescaped " key=" token.
func cefExtension(s string) map[string]string {
	out := map[string]string{}
	type pos struct{ keyStart, valStart int }
	var keys []pos
	for i := 0; i < len(s); i++ {
		if s[i] != '=' || (i > 0 && s[i-1] == '\\') {
			continue
		}
		j := i
		for j > 0 && isCEFKeyChar(s[j-1]) {
			j--
		}
		if j == i || (j > 0 && s[j-1] != ' ') {
			continue
		}
		keys = append(keys, pos{j, i + 1})
	}
	for n, k := range keys {
		end := len(s)
		if n+1 < len(keys) {
			end = keys[n+1].keyStart - 1
		}
		if end < k.valStart {
			end = k.valStart
		}
		val := s[k.valStart:end]
		val = strings.NewReplacer(`\=`, "=", `\\`, `\`, `\n`, "\n", `\r`, "\r").Replace(val)
		out[s[k.keyStart:k.valStart-1]] = strings.TrimSpace(val)
	}
	return out
}

func isCEFKeyChar(c byte) bool {
	return c == '_' || c == '.' || c == '-' || c == '[' || c == ']' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
