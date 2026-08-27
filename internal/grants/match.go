package grants

import "strings"

// Wildcard is the only metacharacter in a grant pattern.
//
// A single "*" is deliberately NOT a metacharacter: it is a real DNS wildcard label ("*.app"), so a
// grant naming it means that literal record and nothing else. Doubling it keeps the two unambiguous.
const Wildcard = "**"

// Match reports whether value satisfies pattern. "**" matches any run of characters, including none;
// every other character is literal. Comparison is case-insensitive.
func Match(pattern, value string) bool {
	p := strings.ToLower(pattern)
	v := strings.ToLower(value)

	segments := strings.Split(p, Wildcard)
	if len(segments) == 1 {
		return p == v
	}

	prefix, suffix := segments[0], segments[len(segments)-1]
	if !strings.HasPrefix(v, prefix) || !strings.HasSuffix(v, suffix) {
		return false
	}
	// The prefix and suffix must not have to overlap to both fit.
	if len(prefix)+len(suffix) > len(v) {
		return false
	}

	// Consume the interior segments left to right; each must appear after the previous one.
	rest := v[len(prefix) : len(v)-len(suffix)]
	for _, seg := range segments[1 : len(segments)-1] {
		if seg == "" {
			continue
		}
		i := strings.Index(rest, seg)
		if i < 0 {
			return false
		}
		rest = rest[i+len(seg):]
	}
	return true
}
