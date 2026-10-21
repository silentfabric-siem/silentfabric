package parse

import "strings"

// KV parses space-separated key=value pairs. Values may be double-quoted
// (with backslash escapes); tokens without "=" are skipped.
func KV(s string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= len(s) || s[i] == ' ' {
			continue // bare token such as "DF" or "SYN"
		}
		key := s[start:i]
		i++ // skip '='
		var val strings.Builder
		if i < len(s) && s[i] == '"' {
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				val.WriteByte(s[i])
				i++
			}
			i++ // closing quote
		} else {
			for i < len(s) && s[i] != ' ' {
				val.WriteByte(s[i])
				i++
			}
		}
		if key != "" {
			out[key] = val.String()
		}
	}
	return out
}
