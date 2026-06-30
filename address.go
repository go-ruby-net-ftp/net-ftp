package netftp

import (
	"regexp"
	"strconv"
	"strings"
)

// Data-connection address extraction: the PASV (227), EPSV (229), and pathname
// (257) reply parsers, byte-for-byte with MRI's parse227 / parse229 / parse257.

var (
	// parse227Re matches MRI: /(?<host>\d+(?:,\d+){3}),(?<port>\d+,\d+)/
	parse227Re = regexp.MustCompile(`(\d+(?:,\d+){3}),(\d+,\d+)`)
	// parse229Re matches MRI: /\((?<d>[!-~])\k<d>\k<d>(?<port>\d+)\k<d>\)/ —
	// the delimiter (any printable [!-~]) repeated three times, then the port,
	// then the delimiter once, inside parentheses. Go's RE2 has no backrefs, so
	// the delimiter equality is checked in code (see Parse229).
	parse229Re = regexp.MustCompile(`\(([!-~])([!-~])([!-~])(\d+)([!-~])\)`)
	// parse257Re matches MRI: /"(([^"]|"")*)"/ — a double-quoted string in which
	// a literal quote is doubled.
	parse257Re = regexp.MustCompile(`"(([^"]|"")*)"`)
)

// pasvIPv4Host turns the comma-separated host group of a PASV reply into a
// dotted-quad address, mirroring parse_pasv_ipv4_host: `s.tr(",", ".")`.
func pasvIPv4Host(s string) string {
	return strings.ReplaceAll(s, ",", ".")
}

// pasvPort folds a comma-separated byte list into a single port, mirroring
// parse_pasv_port: `s.split(",").map(&:to_i).inject { |x, y| (x << 8) + y }`.
// MRI's to_i parses the leading integer of each field (0 for a non-numeric
// field); this reproduces that with the same fold.
func pasvPort(s string) int {
	port := 0
	for _, f := range strings.Split(s, ",") {
		port = (port << 8) + rubyToI(f)
	}
	return port
}

// PasvIPv6Host turns the comma-separated host group of an IPv6 PASV reply into a
// colon-separated hextet address, mirroring parse_pasv_ipv6_host:
// `s.split(",").map { "%02x" % i.to_i }.each_slice(2).map(&:join).join(":")`.
func PasvIPv6Host(s string) string {
	fields := strings.Split(s, ",")
	hex := make([]string, len(fields))
	for i, f := range fields {
		hex[i] = byteHex(rubyToI(f))
	}
	groups := make([]string, 0, (len(hex)+1)/2)
	for i := 0; i < len(hex); i += 2 {
		if i+1 < len(hex) {
			groups = append(groups, hex[i]+hex[i+1])
		} else {
			groups = append(groups, hex[i])
		}
	}
	return strings.Join(groups, ":")
}

// Parse227 parses a 227 (Entering Passive Mode) reply, mirroring MRI parse227.
//
//   - If resp does not start with "227" → FTPReplyError.
//   - If the "(h1,h2,h3,h4,p1,p2)" pattern is absent → FTPProtoError.
//   - Otherwise the port is (p1<<8)+p2.
//
// The host is the seam: MRI returns the encoded h1.h2.h3.h4 when @use_pasv_ip is
// true, otherwise the control socket's remote address. usePasvIP selects between
// the two; remoteAddr supplies the socket's address for the false branch (the
// host passes what the data connection should dial).
func Parse227(resp string, usePasvIP bool, remoteAddr string) (host string, port int, err error) {
	if !strings.HasPrefix(resp, "227") {
		return "", 0, replyErr(resp)
	}
	m := parse227Re.FindStringSubmatch(resp)
	if m == nil {
		return "", 0, protoErr(resp)
	}
	if usePasvIP {
		host = pasvIPv4Host(m[1])
	} else {
		host = remoteAddr
	}
	return host, pasvPort(m[2]), nil
}

// Parse229 parses a 229 (Extended Passive Mode) reply, mirroring MRI parse229.
//
//   - If resp does not start with "229" → FTPReplyError.
//   - If the "(|||port|)" pattern (delimiter repeated three times, then the
//     port, then the delimiter once) is absent → FTPProtoError.
//
// EPSV does not encode a host, so MRI returns the control socket's remote
// address; remoteAddr is that seam value, returned unchanged as host.
func Parse229(resp string, remoteAddr string) (host string, port int, err error) {
	if !strings.HasPrefix(resp, "229") {
		return "", 0, replyErr(resp)
	}
	m := parse229Re.FindStringSubmatch(resp)
	// The four delimiter captures must be identical (MRI's \k<d> backreference).
	if m == nil || m[1] != m[2] || m[1] != m[3] || m[1] != m[5] {
		return "", 0, protoErr(resp)
	}
	p, _ := strconv.Atoi(m[4]) // \d+ guarantees a valid integer.
	return remoteAddr, p, nil
}

// Parse257 extracts the quoted pathname from a 257 reply, mirroring MRI
// parse257.
//
//   - If resp does not start with "257" → FTPReplyError.
//   - Otherwise it returns the contents of the first "..." with doubled quotes
//     ("") collapsed to a single quote. When no quoted string is present MRI's
//     `.to_s` yields "" — this returns "" too.
func Parse257(resp string) (string, error) {
	if !strings.HasPrefix(resp, "257") {
		return "", replyErr(resp)
	}
	m := parse257Re.FindStringSubmatch(resp)
	if m == nil {
		return "", nil
	}
	return strings.ReplaceAll(m[1], `""`, `"`), nil
}
