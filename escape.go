package casbin

import (
	"regexp"
	"strings"
)

func EscapeDots(s string) string {
	var r1 = regexp.MustCompile(`(_)`)
	s = r1.ReplaceAllString(s, `$1$1`)

	var r2 = regexp.MustCompile(`(\.{2,})`)
	s = r2.ReplaceAllString(s, `$1$1`)

	return strings.Replace(s, ".", "_", -1)
}
