package netftp

import "strings"

// Reply-classification flows for the commands whose handling is more than a bare
// voidcmd — delete, the login USER/PASS/ACCT ladder, and the SIZE/SYST/MDTM
// body extraction. These are the pure decision functions MRI runs over a reply;
// the host issues the command, reads the reply via the seam, and calls these.

// LoginStep is one rung of MRI's login USER → PASS → ACCT ladder.
type LoginStep int

const (
	// LoginSendPass means the previous reply began with '3', so send PASS next.
	// When the credential for the next step is missing MRI raises FTPReplyError
	// (see LoginNext's error return).
	LoginSendPass LoginStep = iota
	// LoginSendAcct means send ACCT next (the reply still began with '3').
	LoginSendAcct
	// LoginDone means the ladder is complete; the final reply must start with
	// '2' or LoginNext returns FTPReplyError.
	LoginDone
)

// LoginNext decides the next login action from the latest reply, mirroring the
// flow in MRI's login. afterPass distinguishes the reply to USER (false) from
// the reply to PASS (true), so a '3' reply maps to LoginSendPass or
// LoginSendAcct respectively. A reply that does not begin with '3' ends the
// ladder: LoginDone, with FTPReplyError when it does not begin with '2'.
func LoginNext(reply string, afterPass bool) (LoginStep, error) {
	if strings.HasPrefix(reply, "3") {
		if afterPass {
			return LoginSendAcct, nil
		}
		return LoginSendPass, nil
	}
	if !strings.HasPrefix(reply, "2") {
		return LoginDone, replyErr(reply)
	}
	return LoginDone, nil
}

// AnonymousLogin reports the password Net::FTP substitutes when logging in as
// "anonymous" with no password: ("anonymous@", true). For any other user, or
// when a password is already supplied, it returns ("", false).
func AnonymousLogin(user string, passwdGiven bool) (string, bool) {
	if user == "anonymous" && !passwdGiven {
		return AnonymousPassword, true
	}
	return "", false
}

// CheckDelete classifies the reply to a DELE command, mirroring MRI delete:
//
//   - "250…"            → success (nil).
//   - "5…"              → FTPPermError.
//   - anything else     → FTPReplyError.
func CheckDelete(resp string) error {
	switch {
	case strings.HasPrefix(resp, "250"):
		return nil
	case strings.HasPrefix(resp, "5"):
		return permErr(resp)
	default:
		return replyErr(resp)
	}
}

// CheckRenameFrom classifies the reply to an RNFR command, mirroring MRI rename:
// a reply not beginning with '3' is an FTPReplyError; otherwise RNTO follows.
func CheckRenameFrom(resp string) error {
	if !strings.HasPrefix(resp, "3") {
		return replyErr(resp)
	}
	return nil
}

// SizeResult extracts the file size from a SIZE reply, mirroring MRI size:
// a reply not beginning with "213" is an FTPReplyError; otherwise the body after
// "NNN " is read as an integer (String#to_i).
func SizeResult(resp string) (int, error) {
	if !strings.HasPrefix(resp, "213") {
		return 0, replyErr(resp)
	}
	body, _ := ReplyBody(resp)
	return rubyToI(body), nil
}

// SystResult extracts the system string from a SYST reply, mirroring MRI system:
// a reply not beginning with "215" is an FTPReplyError; otherwise the body after
// "NNN " is returned.
func SystResult(resp string) (string, error) {
	if !strings.HasPrefix(resp, "215") {
		return "", replyErr(resp)
	}
	body, _ := ReplyBody(resp)
	return body, nil
}

// MdtmResult extracts the raw "YYYYMMDDhhmmss" timestamp from an MDTM reply,
// mirroring MRI mdtm: when the reply begins with "213" the body after "NNN " is
// returned (ok true); otherwise MRI returns nil — here ok is false.
func MdtmResult(resp string) (string, bool) {
	if !strings.HasPrefix(resp, "213") {
		return "", false
	}
	body, _ := ReplyBody(resp)
	return body, true
}

// AbortAccepted reports whether an ABOR reply is one MRI accepts (426, 226, or
// 225); otherwise MRI raises FTPProtoError. The reply's first three characters
// are tested.
func AbortAccepted(resp string) bool {
	code := ReplyCode(resp)
	return code == "426" || code == "226" || code == "225"
}
