package netftp

import "strconv"

// Small numeric helpers that reproduce the exact slices of Ruby semantics
// Net::FTP relies on (String#to_i, String#to_i(8), Integer#to_s, "%02x").

// itoa is base-10 Integer#to_s.
func itoa(n int) string { return strconv.Itoa(n) }

// byteHex is Ruby's `"%02x" % n` for the non-negative byte values PASV/EPSV
// use: lowercase hex, zero-padded to at least two digits. PASV byte fields come
// from String#to_i on a comma-separated list, which never yields a negative for
// a well-formed reply; wider values (>255) still format faithfully via %02x.
func byteHex(n int) string {
	s := strconv.FormatInt(int64(n), 16)
	if len(s) < 2 {
		return "0" + s
	}
	return s
}

// rubyToI reproduces String#to_i (base 10): skip leading ASCII whitespace, take
// an optional sign, then the leading run of decimal digits, allowing single
// underscores between digits. A string with no leading digits yields 0.
func rubyToI(s string) int { return rubyToIBase(s, 10) }

// rubyToIBase reproduces String#to_i(base) for base 10 and 8 (the only bases
// Net::FTP's fact parsers use). Leading whitespace and an optional sign are
// consumed, then digits valid for the base, with single underscores permitted
// between digits.
func rubyToIBase(s string, base int) int {
	i := 0
	n := len(s)
	for i < n && isSpace(s[i]) {
		i++
	}
	neg := false
	if i < n && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	val := 0
	lastDigit := false
	any := false
	for i < n {
		c := s[i]
		if c == '_' {
			// An underscore is only allowed immediately after a digit, and may
			// not be the last character of the numeric run.
			if !lastDigit || i+1 >= n || digitVal(s[i+1], base) < 0 {
				break
			}
			lastDigit = false
			i++
			continue
		}
		d := digitVal(c, base)
		if d < 0 {
			break
		}
		val = val*base + d
		any = true
		lastDigit = true
		i++
	}
	if !any {
		return 0
	}
	if neg {
		return -val
	}
	return val
}

func isSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

func digitVal(b byte, base int) int {
	var d int
	switch {
	case b >= '0' && b <= '9':
		d = int(b - '0')
	case b >= 'a' && b <= 'z':
		d = int(b-'a') + 10
	case b >= 'A' && b <= 'Z':
		d = int(b-'A') + 10
	default:
		return -1
	}
	if d >= base {
		return -1
	}
	return d
}
