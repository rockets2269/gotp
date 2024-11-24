package internal

import (
	"net/url"
	"sort"
	"strings"
)

func EncodeQuery(v url.Values) string {
	if v == nil {
		return ""
	}

	var buf strings.Builder

	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		vs := v[k]
		keyEscaped := url.PathEscape(k)
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}

			buf.WriteString(keyEscaped)
			buf.WriteByte('=')
			buf.WriteString(url.PathEscape(v))
		}
	}

	return buf.String()
}
