package netftp

import "strings"

// Reply parsing — the deterministic half of Net::FTP's getline / getmultiline /
// getresp / voidresp. The socket read is the seam: the host supplies the raw
// lines (already EOF-checked); this package strips terminators, joins a
// multiline block, and classifies the 3-digit code exactly as MRI does.

// stripLineTerminator removes a single trailing CRLF / LF / CR, mirroring MRI's
// getline: `line.sub!(/(\r\n|\n|\r)\z/n, "")`.
func stripLineTerminator(line string) string {
	if strings.HasSuffix(line, "\r\n") {
		return line[:len(line)-2]
	}
	if n := len(line); n > 0 {
		if c := line[n-1]; c == '\n' || c == '\r' {
			return line[:n-1]
		}
	}
	return line
}

// Sanitize hides the password in a PASS command for debug output, mirroring
// MRI's sanitize: a line matching /^PASS /i keeps its first five characters and
// has the rest replaced with '*'. Any other line is returned unchanged.
func Sanitize(s string) string {
	if len(s) >= 5 && strings.EqualFold(s[:5], "PASS ") {
		return s[:5] + strings.Repeat("*", len(s)-5)
	}
	return s
}

// multilineCode returns the leading code of a multiline reply's first line —
// MRI's `lines.last.slice(/\A([0-9a-zA-Z]{3})-/, 1)`: three [0-9A-Za-z]
// characters immediately followed by '-'. The second result reports whether the
// reply is multiline (a continuation follows).
func multilineCode(line string) (string, bool) {
	if len(line) >= 4 && line[3] == '-' && isReplyCode(line[:3]) {
		return line[:3], true
	}
	return "", false
}

func isReplyCode(c string) bool {
	if len(c) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		b := c[i]
		if !(b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z') {
			return false
		}
	}
	return true
}

// LineReader yields successive raw lines from the control connection. It is the
// socket seam: returning an error stands in for MRI's EOFError / read failure.
type LineReader func() (string, error)

// GetMultiline assembles one complete reply from the control connection,
// mirroring MRI's getmultiline. It reads the first line; if that line is a
// multiline opener ("NNN-..."), it keeps reading until a line begins with
// "NNN " (the code followed by a space). The lines are joined with "\n" and a
// trailing "\n" is appended, exactly as MRI returns them.
//
// read is the host-supplied socket seam; any error it returns (EOF, I/O) is
// propagated unchanged.
func GetMultiline(read LineReader) (string, error) {
	first, err := read()
	if err != nil {
		return "", err
	}
	lines := []string{stripLineTerminator(first)}
	if code, multi := multilineCode(lines[0]); multi {
		delimiter := code + " "
		for {
			next, err := read()
			if err != nil {
				return "", err
			}
			line := stripLineTerminator(next)
			lines = append(lines, line)
			if strings.HasPrefix(line, delimiter) {
				break
			}
		}
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// ReplyCode returns the three-character reply code at the start of an assembled
// reply (MRI's `@last_response[0, 3]`). For a reply shorter than three
// characters it returns the whole reply, matching Ruby's slice semantics.
func ReplyCode(resp string) string {
	if len(resp) < 3 {
		return resp
	}
	return resp[:3]
}

// ClassifyReply applies MRI's getresp classification to an assembled reply:
//
//   - 1yz / 2yz / 3yz  → returns the reply with a nil error (success).
//   - 4yz              → FTPTempError.
//   - 5yz              → FTPPermError.
//   - anything else    → FTPProtoError.
//
// The first byte of the code drives the decision, as in MRI's case/when on
// /\A[123]/, /\A4/, /\A5/.
func ClassifyReply(resp string) (string, error) {
	switch {
	case len(resp) >= 1 && (resp[0] == '1' || resp[0] == '2' || resp[0] == '3'):
		return resp, nil
	case len(resp) >= 1 && resp[0] == '4':
		return "", tempErr(resp)
	case len(resp) >= 1 && resp[0] == '5':
		return "", permErr(resp)
	default:
		return "", protoErr(resp)
	}
}

// GetResp reads one reply (GetMultiline) and classifies it (ClassifyReply),
// mirroring MRI's getresp. On success it returns the assembled reply; on a
// 4yz/5yz/other reply it returns the matching FTPError; a read error from the
// seam is propagated unchanged.
func GetResp(read LineReader) (string, error) {
	resp, err := GetMultiline(read)
	if err != nil {
		return "", err
	}
	return ClassifyReply(resp)
}

// VoidResp reads a reply and requires it to begin with '2', mirroring MRI's
// voidresp (`raise FTPReplyError, resp if !resp.start_with?("2")`). Note MRI
// calls getresp first, so a 4yz/5yz reply surfaces as Temp/Perm before the
// "starts with 2" check; this preserves that ordering.
func VoidResp(read LineReader) error {
	resp, err := GetResp(read)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, "2") {
		return replyErr(resp)
	}
	return nil
}

// ReplyBody returns the text after the 3-character code and one space, mirroring
// MRI's get_body: `resp.slice(/\A[0-9a-zA-Z]{3} (.*)$/, 1)`. The match is
// anchored at the start and stops at the first newline ($). It returns "", false
// when the reply does not start with "NNN " (a valid code plus a space).
func ReplyBody(resp string) (string, bool) {
	if len(resp) < 4 || !isReplyCode(resp[:3]) || resp[3] != ' ' {
		return "", false
	}
	rest := resp[4:]
	if i := strings.IndexByte(rest, '\n'); i >= 0 {
		rest = rest[:i]
	}
	return rest, true
}
