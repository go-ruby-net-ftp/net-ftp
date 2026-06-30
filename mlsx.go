package netftp

import (
	"regexp"
	"strings"
)

// MLSD / MLST entry parsing — MRI's parse_mlsx_entry plus the FACT_PARSERS table
// and the MLSxEntry value object. Every fact value is parsed exactly as MRI
// parses it (decimal, octal, time, case-folded, or verbatim), and the perm-bit
// predicates mirror MLSxEntry's.

// FactValue is a parsed MLSx fact value. Exactly one shape is populated,
// selected by Kind. The host maps these onto Ruby values (Integer, Time, String).
type FactValue struct {
	Kind FactKind
	// Str holds the value for string-typed facts (verbatim, case-folded, or the
	// raw text for any fact without a dedicated parser).
	Str string
	// Int holds the value for decimal/octal-typed facts (size, unix.mode, …).
	Int int
	// Time holds the value for time-typed facts (modify, create, unix.*time).
	Time MLSxTime
}

// FactKind tags the shape of a FactValue.
type FactKind int

const (
	// FactString is a textual fact (Net::FTP's CASE_DEPENDENT/INDEPENDENT
	// parsers, and the default for unknown facts).
	FactString FactKind = iota
	// FactInt is an integer fact (DECIMAL_PARSER / OCTAL_PARSER).
	FactInt
	// FactTime is a time fact (TIME_PARSER), exposed as MLSxTime.
	FactTime
)

// MLSxTime is a parsed MLSx time-val (MRI's TIME_PARSER result, always UTC for
// MLSx facts). The components match Ruby's Time accessors; Nsec carries the
// fractional seconds (".fractions".to_r * 1_000_000 → microseconds, here in
// nanoseconds).
type MLSxTime struct {
	Year, Month, Day int
	Hour, Min, Sec   int
	Nsec             int
}

// timeValRe matches MRI's TIME_PARSER pattern (unanchored at the end):
// YYYYMMDDhhmmss with an optional ".fractions" of 1..17 digits.
var timeValRe = regexp.MustCompile(`^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,17}))?`)

// parseTimeVal reproduces TIME_PARSER. On a non-matching value it returns an
// FTPProtoError "invalid time-val: <value>" (with MRI's 100-char truncation:
// values longer than 100 chars are clipped to the first 97 plus "...").
func parseTimeVal(value string) (MLSxTime, error) {
	m := timeValRe.FindStringSubmatch(value)
	if m == nil {
		v := value
		if len([]rune(v)) > 100 {
			r := []rune(v)
			v = string(r[:97]) + "..."
		}
		return MLSxTime{}, protoErr("invalid time-val: " + v)
	}
	t := MLSxTime{
		Year:  rubyToI(m[1]),
		Month: rubyToI(m[2]),
		Day:   rubyToI(m[3]),
		Hour:  rubyToI(m[4]),
		Min:   rubyToI(m[5]),
		Sec:   rubyToI(m[6]),
	}
	if frac := m[7]; frac != "" {
		t.Nsec = fractionToNsec(frac)
	}
	return t, nil
}

// fractionToNsec converts a fractional-seconds digit string to nanoseconds,
// mirroring `".#{fractions}".to_r * 1_000_000` (microseconds) scaled to nsec.
// It uses exact integer arithmetic so no precision is lost for any 1..17-digit
// fraction.
func fractionToNsec(frac string) int {
	// value = frac / 10^len(frac) seconds → nsec = frac * 10^(9-len(frac)),
	// or frac / 10^(len(frac)-9) when the fraction is finer than nanoseconds.
	num := 0
	for i := 0; i < len(frac); i++ {
		num = num*10 + int(frac[i]-'0')
	}
	exp := 9 - len(frac)
	if exp >= 0 {
		for ; exp > 0; exp-- {
			num *= 10
		}
		return num
	}
	for ; exp < 0; exp++ {
		num /= 10
	}
	return num
}

// caseFold is CASE_INDEPENDENT_PARSER: value.downcase. MLSx values are ASCII, so
// ASCII lowercasing matches Ruby's String#downcase here.
func caseFold(s string) string { return strings.ToLower(s) }

// parseFact applies the FACT_PARSERS entry for a (lower-cased) fact name to its
// value, returning the typed FactValue. Unknown facts use the default
// CASE_DEPENDENT_PARSER (verbatim string).
func parseFact(name, value string) (FactValue, error) {
	switch name {
	case "size", "unix.owner", "unix.group":
		return FactValue{Kind: FactInt, Int: rubyToI(value)}, nil // DECIMAL_PARSER
	case "unix.mode":
		return FactValue{Kind: FactInt, Int: rubyToIBase(value, 8)}, nil // OCTAL_PARSER
	case "modify", "create", "unix.ctime", "unix.atime":
		t, err := parseTimeVal(value) // TIME_PARSER
		if err != nil {
			return FactValue{}, err
		}
		return FactValue{Kind: FactTime, Time: t}, nil
	case "type", "perm", "lang", "media-type", "charset":
		return FactValue{Kind: FactString, Str: caseFold(value)}, nil // CASE_INDEPENDENT_PARSER
	default:
		// CASE_DEPENDENT_PARSER (incl. "unique") and any unknown fact.
		return FactValue{Kind: FactString, Str: value}, nil
	}
}

// MLSxEntry is a parsed MLST/MLSD entry: the facts (keyed by lower-cased name)
// and the pathname, mirroring Net::FTP::MLSxEntry.
type MLSxEntry struct {
	// Facts maps each fact name (already lower-cased, as MRI stores them) to its
	// parsed value. Insertion-order is not preserved (Go map); use FactOrder for
	// the order facts appeared, if needed.
	Facts map[string]FactValue
	// FactOrder lists fact names in the order they appeared in the entry — MRI's
	// Hash preserves insertion order; this exposes the same sequence.
	FactOrder []string
	// Pathname is the entry's pathname (the text after the first space).
	Pathname string
}

// factScanRe matches MRI's `facts.scan(/(.*?)=(.*?);/)`: a non-greedy
// name=value pair terminated by a semicolon.
var factScanRe = regexp.MustCompile(`(?s)(.*?)=(.*?);`)

// ParseMLSxEntry parses one MLST/MLSD line into an MLSxEntry, mirroring MRI
// parse_mlsx_entry:
//
//   - The line is chomped (trailing "\n"/"\r\n"/"\r" removed) then split on the
//     first space into the facts blob and the pathname.
//   - A line with no space (no pathname) → FTPProtoError with the raw entry.
//   - Each "name=value;" pair is scanned out; the name is lower-cased and its
//     value parsed by the matching FACT_PARSERS entry.
//
// A fact value that fails its parser (an invalid time-val) propagates that
// FTPProtoError, exactly as the lambda would raise inside MRI.
func ParseMLSxEntry(entry string) (MLSxEntry, error) {
	chomped := rubyChomp(entry)
	facts, pathname, found := splitFirstSpace(chomped)
	if !found {
		return MLSxEntry{}, protoErr(entry)
	}
	out := MLSxEntry{
		Facts:    map[string]FactValue{},
		Pathname: pathname,
	}
	for _, m := range factScanRe.FindAllStringSubmatch(facts, -1) {
		name := caseFold(m[1])
		fv, err := parseFact(name, m[2])
		if err != nil {
			return MLSxEntry{}, err
		}
		if _, seen := out.Facts[name]; !seen {
			out.FactOrder = append(out.FactOrder, name)
		}
		out.Facts[name] = fv
	}
	return out, nil
}

// rubyChomp removes a single trailing record separator ("\r\n", "\n", or "\r"),
// matching String#chomp with the default separator MRI uses before splitting.
func rubyChomp(s string) string {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2]
	}
	if n := len(s); n > 0 {
		if c := s[n-1]; c == '\n' || c == '\r' {
			return s[:n-1]
		}
	}
	return s
}

// splitFirstSpace mirrors `entry.chomp.split(/ /, 2)`: it splits on the first
// space into (facts, pathname). When there is no space, found is false (MRI's
// `pathname` is nil → FTPProtoError).
func splitFirstSpace(s string) (head, rest string, found bool) {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// typeString returns the lower-cased "type" fact, or "" when absent.
func (e MLSxEntry) typeString() string {
	if v, ok := e.Facts["type"]; ok {
		return v.Str
	}
	return ""
}

// permString returns the lower-cased "perm" fact, or "" when absent.
func (e MLSxEntry) permString() string {
	if v, ok := e.Facts["perm"]; ok {
		return v.Str
	}
	return ""
}

// IsFile reports whether the entry's type fact is "file" (MLSxEntry#file?).
func (e MLSxEntry) IsFile() bool { return e.typeString() == "file" }

// dirTypeRe matches MRI's MLSxEntry#directory? test: /\A[cp]?dir\z/.
var dirTypeRe = regexp.MustCompile(`^[cp]?dir$`)

// IsDirectory reports whether the entry's type fact is dir, cdir, or pdir
// (MLSxEntry#directory?).
func (e MLSxEntry) IsDirectory() bool { return dirTypeRe.MatchString(e.typeString()) }

// permHas reports whether the perm fact contains the given permission letter,
// the predicate every MLSxEntry perm-query (appendable?, readable?, …) uses
// (`facts["perm"].include?(?x)`). Letters are matched against the case-folded
// perm value, as MRI stores perm lower-cased.
func (e MLSxEntry) permHas(c byte) bool {
	return strings.IndexByte(e.permString(), c) >= 0
}

// Appendable reports MLSxEntry#appendable? (perm includes 'a').
func (e MLSxEntry) Appendable() bool { return e.permHas('a') }

// Creatable reports MLSxEntry#creatable? (perm includes 'c').
func (e MLSxEntry) Creatable() bool { return e.permHas('c') }

// Deletable reports MLSxEntry#deletable? (perm includes 'd').
func (e MLSxEntry) Deletable() bool { return e.permHas('d') }

// Enterable reports MLSxEntry#enterable? (perm includes 'e').
func (e MLSxEntry) Enterable() bool { return e.permHas('e') }

// Renamable reports MLSxEntry#renamable? (perm includes 'f').
func (e MLSxEntry) Renamable() bool { return e.permHas('f') }

// Listable reports MLSxEntry#listable? (perm includes 'l').
func (e MLSxEntry) Listable() bool { return e.permHas('l') }

// DirectoryMakable reports MLSxEntry#directory_makable? (perm includes 'm').
func (e MLSxEntry) DirectoryMakable() bool { return e.permHas('m') }

// Purgeable reports MLSxEntry#purgeable? (perm includes 'p').
func (e MLSxEntry) Purgeable() bool { return e.permHas('p') }

// Readable reports MLSxEntry#readable? (perm includes 'r').
func (e MLSxEntry) Readable() bool { return e.permHas('r') }

// Writable reports MLSxEntry#writable? (perm includes 'w').
func (e MLSxEntry) Writable() bool { return e.permHas('w') }
