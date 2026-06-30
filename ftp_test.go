package netftp

import (
	"errors"
	"io"
	"reflect"
	"testing"
)

// Deterministic, Ruby-free tests. These alone exercise every branch so the
// no-ruby CI lanes (and qemu arch lanes) keep coverage at 100%. The oracle_test
// suite additionally pins the behaviour to the live `ruby` binary where present.

// --- reply parsing -----------------------------------------------------------

func TestStripLineTerminator(t *testing.T) {
	cases := map[string]string{
		"abc\r\n": "abc",
		"abc\n":   "abc",
		"abc\r":   "abc",
		"abc":     "abc",
		"":        "",
		"\n":      "",
	}
	for in, want := range cases {
		if got := stripLineTerminator(in); got != want {
			t.Errorf("stripLineTerminator(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"PASS secret": "PASS ******",
		"pass secret": "pass ******",
		"PASS ":       "PASS ",
		"USER bob":    "USER bob",
		"PAS":         "PAS",
		"":            "",
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMultilineCodeAndIsReplyCode(t *testing.T) {
	if c, multi := multilineCode("220-hi"); !multi || c != "220" {
		t.Errorf("multilineCode(220-) = %q,%v", c, multi)
	}
	if _, multi := multilineCode("220 hi"); multi {
		t.Error("single-line should not be multiline")
	}
	if _, multi := multilineCode("22-"); multi {
		t.Error("too short should not be multiline")
	}
	if _, multi := multilineCode("!!!-x"); multi {
		t.Error("non-code prefix should not be multiline")
	}
	if isReplyCode("12") {
		t.Error("length 2 is not a reply code")
	}
	if isReplyCode("12@") {
		t.Error("'@' is not allowed in a reply code")
	}
	if !isReplyCode("aB9") {
		t.Error("alnum triple is a reply code")
	}
}

// scriptReader turns a list of lines (and an optional terminal error) into a
// LineReader seam.
func scriptReader(lines []string, end error) LineReader {
	i := 0
	return func() (string, error) {
		if i >= len(lines) {
			if end != nil {
				return "", end
			}
			return "", io.EOF
		}
		l := lines[i]
		i++
		return l, nil
	}
}

func TestGetMultiline(t *testing.T) {
	// Single line.
	got, err := GetMultiline(scriptReader([]string{"200 OK\r\n"}, nil))
	if err != nil || got != "200 OK\n" {
		t.Fatalf("single: %q %v", got, err)
	}
	// Multiline block.
	got, err = GetMultiline(scriptReader([]string{"220-line1\r\n", "extra\r\n", "220 done\r\n"}, nil))
	if err != nil || got != "220-line1\nextra\n220 done\n" {
		t.Fatalf("multi: %q %v", got, err)
	}
	// Read error on first line.
	want := errors.New("boom")
	if _, err := GetMultiline(scriptReader(nil, want)); !errors.Is(err, want) {
		t.Fatalf("first-line error: %v", err)
	}
	// Read error mid-multiline (no closing delimiter before exhaustion).
	if _, err := GetMultiline(scriptReader([]string{"220-x\r\n"}, want)); !errors.Is(err, want) {
		t.Fatalf("mid error: %v", err)
	}
}

func TestReplyCodeAndClassify(t *testing.T) {
	if ReplyCode("220 hi") != "220" {
		t.Error("ReplyCode")
	}
	if ReplyCode("22") != "22" {
		t.Error("ReplyCode short")
	}
	for _, c := range []struct {
		resp string
		kind FTPErrorKind
		ok   bool
	}{
		{"150 x", 0, true},
		{"220 x", 0, true},
		{"331 x", 0, true},
		{"450 x", KindTemp, false},
		{"550 x", KindPerm, false},
		{"678 x", KindProto, false},
		{"", KindProto, false},
	} {
		got, err := ClassifyReply(c.resp)
		if c.ok {
			if err != nil || got != c.resp {
				t.Errorf("ClassifyReply(%q) = %q,%v", c.resp, got, err)
			}
			continue
		}
		var fe *FTPError
		if !errors.As(err, &fe) || fe.Kind != c.kind {
			t.Errorf("ClassifyReply(%q) kind = %v, want %v", c.resp, err, c.kind)
		}
	}
}

func TestGetResp(t *testing.T) {
	got, err := GetResp(scriptReader([]string{"200 OK\r\n"}, nil))
	if err != nil || got != "200 OK\n" {
		t.Fatalf("ok: %q %v", got, err)
	}
	// 5yz reply → perm error.
	_, err = GetResp(scriptReader([]string{"500 no\r\n"}, nil))
	var fe *FTPError
	if !errors.As(err, &fe) || fe.Kind != KindPerm {
		t.Fatalf("perm: %v", err)
	}
	// Read error propagates.
	want := errors.New("io")
	if _, err := GetResp(scriptReader(nil, want)); !errors.Is(err, want) {
		t.Fatalf("read err: %v", err)
	}
}

func TestVoidResp(t *testing.T) {
	if err := VoidResp(scriptReader([]string{"200 OK\r\n"}, nil)); err != nil {
		t.Fatalf("2yz should pass: %v", err)
	}
	// 1yz/3yz pass classification but fail the "starts with 2" check.
	err := VoidResp(scriptReader([]string{"331 need pass\r\n"}, nil))
	var fe *FTPError
	if !errors.As(err, &fe) || fe.Kind != KindReply {
		t.Fatalf("non-2yz: %v", err)
	}
	// 5yz surfaces as perm before the start-with-2 check (ordering).
	err = VoidResp(scriptReader([]string{"550 no\r\n"}, nil))
	if !errors.As(err, &fe) || fe.Kind != KindPerm {
		t.Fatalf("perm ordering: %v", err)
	}
	// Read error propagates.
	want := errors.New("io")
	if err := VoidResp(scriptReader(nil, want)); !errors.Is(err, want) {
		t.Fatalf("read err: %v", err)
	}
}

func TestReplyBody(t *testing.T) {
	if b, ok := ReplyBody("215 UNIX Type: L8"); !ok || b != "UNIX Type: L8" {
		t.Errorf("body = %q,%v", b, ok)
	}
	// Multiline: body stops at first newline.
	if b, ok := ReplyBody("213 12345\nmore"); !ok || b != "12345" {
		t.Errorf("body nl = %q,%v", b, ok)
	}
	if _, ok := ReplyBody("213"); ok {
		t.Error("no space → no body")
	}
	// MRI's get_body regex is /\A[0-9a-zA-Z]{3} (.*)$/, so an alnum code such as
	// "21X" is accepted and yields a body.
	if b, ok := ReplyBody("21X file"); !ok || b != "file" {
		t.Errorf("alnum code body = %q,%v", b, ok)
	}
	// A code containing a non-alnum byte is rejected.
	if _, ok := ReplyBody("2!1 file"); ok {
		t.Error("non-alnum code → no body")
	}
	if _, ok := ReplyBody("213-multi"); ok {
		t.Error("dash separator → no body")
	}
}

// --- errors ------------------------------------------------------------------

func TestErrorClassNames(t *testing.T) {
	cases := map[FTPErrorKind]string{
		KindReply:        "Net::FTPReplyError",
		KindTemp:         "Net::FTPTempError",
		KindPerm:         "Net::FTPPermError",
		KindProto:        "Net::FTPProtoError",
		KindConnection:   "Net::FTPConnectionError",
		FTPErrorKind(99): "Net::FTPError",
	}
	for k, want := range cases {
		e := &FTPError{Kind: k, Message: "m"}
		if e.ClassName() != want {
			t.Errorf("kind %d ClassName = %q, want %q", k, e.ClassName(), want)
		}
	}
	e := &FTPError{Kind: KindPerm, Message: "550 nope"}
	if e.Error() != "550 nope" {
		t.Errorf("Error() = %q", e.Error())
	}
}

// --- commands ----------------------------------------------------------------

func TestPutLine(t *testing.T) {
	got, err := PutLine("USER bob")
	if err != nil || got != "USER bob\r\n" {
		t.Fatalf("PutLine = %q,%v", got, err)
	}
	if _, err := PutLine("bad\nline"); !errors.Is(err, ErrLineHasCRLF) {
		t.Fatalf("CRLF reject = %v", err)
	}
	if _, err := PutLine("bad\rline"); !errors.Is(err, ErrLineHasCRLF) {
		t.Fatalf("CR reject = %v", err)
	}
}

func TestCommandBuilders(t *testing.T) {
	cases := []struct {
		got, want string
	}{
		{UserCommand("bob"), "USER bob"},
		{PassCommand("pw"), "PASS pw"},
		{AcctCommand("acct"), "ACCT acct"},
		{TypeCommand(true), "TYPE I"},
		{TypeCommand(false), "TYPE A"},
		{CwdCommand("/tmp"), "CWD /tmp"},
		{CdupCommand, "CDUP"},
		{PwdCommand, "PWD"},
		{NlstCommand(""), "NLST"},
		{NlstCommand("/d"), "NLST /d"},
		{ListCommand(), "LIST"},
		{ListCommand("-l", "/d"), "LIST -l /d"},
		{MlsdCommand(""), "MLSD"},
		{MlsdCommand("/d"), "MLSD /d"},
		{MlstCommand(""), "MLST"},
		{MlstCommand("/f"), "MLST /f"},
		{RetrCommand("f"), "RETR f"},
		{StorCommand("f"), "STOR f"},
		{DeleCommand("f"), "DELE f"},
		{RnfrCommand("a"), "RNFR a"},
		{RntoCommand("b"), "RNTO b"},
		{MkdCommand("d"), "MKD d"},
		{RmdCommand("d"), "RMD d"},
		{SizeCommand("f"), "SIZE f"},
		{MdtmCommand("f"), "MDTM f"},
		{SystCommand, "SYST"},
		{StatCommand(""), "STAT"},
		{StatCommand("/p"), "STAT /p"},
		{FeatCommand, "FEAT"},
		{NoopCommand, "NOOP"},
		{QuitCommand, "QUIT"},
		{AborCommand, "ABOR"},
		{PasvCommand, "PASV"},
		{EpsvCommand, "EPSV"},
		{HelpCommand(""), "HELP"},
		{HelpCommand("SITE"), "HELP SITE"},
		{SiteCommand("CHMOD 644 f"), "SITE CHMOD 644 f"},
		{OptionCommand("UTF8", ""), "OPTS UTF8"},
		{OptionCommand("MLST", "size;type;"), "OPTS MLST size;type;"},
		{SendPort("192.168.0.1", 1930), "PORT 192,168,0,1,7,138"},
		{SendEPort("::1", 6446), "EPRT |2|::1|6446|"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("command = %q, want %q", c.got, c.want)
		}
	}
}

func TestAnonymousPassword(t *testing.T) {
	if AnonymousPassword != "anonymous@" {
		t.Error("AnonymousPassword")
	}
}

// --- address parsing ---------------------------------------------------------

func TestParse227(t *testing.T) {
	// use_pasv_ip = true → host from the reply.
	host, port, err := Parse227("227 Entering Passive Mode (192,168,0,1,7,138)", true, "10.0.0.9")
	if err != nil || host != "192.168.0.1" || port != 1930 {
		t.Fatalf("usePasvIP: %q %d %v", host, port, err)
	}
	// use_pasv_ip = false → host from the seam (remote address).
	host, port, err = Parse227("227 Entering Passive Mode (192,168,0,1,7,138)", false, "10.0.0.9")
	if err != nil || host != "10.0.0.9" || port != 1930 {
		t.Fatalf("seam host: %q %d %v", host, port, err)
	}
	// Wrong code → reply error.
	if _, _, err := Parse227("500 bad", true, ""); !isKind(err, KindReply) {
		t.Fatalf("wrong code: %v", err)
	}
	// No tuple → proto error.
	if _, _, err := Parse227("227 nothing here", true, ""); !isKind(err, KindProto) {
		t.Fatalf("no tuple: %v", err)
	}
}

func TestParse229(t *testing.T) {
	host, port, err := Parse229("229 Entering Extended Passive Mode (|||6446|)", "2001:db8::1")
	if err != nil || host != "2001:db8::1" || port != 6446 {
		t.Fatalf("ok: %q %d %v", host, port, err)
	}
	if _, _, err := Parse229("500 bad", "x"); !isKind(err, KindReply) {
		t.Fatalf("wrong code: %v", err)
	}
	if _, _, err := Parse229("229 no parens", "x"); !isKind(err, KindProto) {
		t.Fatalf("no parens: %v", err)
	}
	// Mismatched delimiters → proto error (regex matches printable chars but the
	// four delimiters differ).
	if _, _, err := Parse229("229 (|!|6446|)", "x"); !isKind(err, KindProto) {
		t.Fatalf("delim mismatch: %v", err)
	}
}

func TestParse257(t *testing.T) {
	p, err := Parse257(`257 "/home/user" created`)
	if err != nil || p != "/home/user" {
		t.Fatalf("ok: %q %v", p, err)
	}
	// Doubled quotes collapse.
	p, err = Parse257(`257 "/a""b" is the current directory`)
	if err != nil || p != `/a"b` {
		t.Fatalf("dq: %q %v", p, err)
	}
	// Wrong code.
	if _, err := Parse257("500 bad"); !isKind(err, KindReply) {
		t.Fatalf("wrong code: %v", err)
	}
	// No quoted string → "" (MRI .to_s).
	if p, err := Parse257("257 created without quotes"); err != nil || p != "" {
		t.Fatalf("no quote: %q %v", p, err)
	}
}

func TestPasvHostHelpers(t *testing.T) {
	if got := pasvIPv4Host("192,168,0,1"); got != "192.168.0.1" {
		t.Errorf("ipv4 host = %q", got)
	}
	if got := pasvPort("7,138"); got != 1930 {
		t.Errorf("port = %d", got)
	}
	if got := PasvIPv6Host("16,1,16,2,16,3,16,4,16,5,16,6,16,7,16,8"); got != "1001:1002:1003:1004:1005:1006:1007:1008" {
		t.Errorf("ipv6 host = %q", got)
	}
	// Odd field count exercises the trailing-single-hextet branch.
	if got := PasvIPv6Host("1,2,3"); got != "0102:03" {
		t.Errorf("ipv6 odd = %q", got)
	}
}

// --- conv --------------------------------------------------------------------

func TestRubyToI(t *testing.T) {
	cases := []struct {
		s    string
		base int
		want int
	}{
		{"42", 10, 42},
		{"  42xyz", 10, 42},
		{"-5", 10, -5},
		{"+7", 8, 7},
		{"0755", 8, 493},
		{"0x10", 8, 0},
		{"abc", 10, 0},
		{"12_3", 10, 123},
		{"1_", 10, 1},
		{"_1", 10, 0},
		{"1__2", 10, 1},
		{"", 10, 0},
		{"7f", 16, 127},
		{"1@2", 10, 1},  // '@' is outside every digit class → stops the run
		{"78", 8, 7},    // '8' is a digit but >= base 8 → stops the octal run
		{"FF", 16, 255}, // uppercase hex digits
	}
	for _, c := range cases {
		if got := rubyToIBase(c.s, c.base); got != c.want {
			t.Errorf("rubyToIBase(%q,%d) = %d, want %d", c.s, c.base, got, c.want)
		}
	}
	if rubyToI("99") != 99 {
		t.Error("rubyToI base-10 wrapper")
	}
}

func TestByteHex(t *testing.T) {
	cases := map[int]string{0: "00", 1: "01", 15: "0f", 16: "10", 255: "ff", 256: "100"}
	for n, want := range cases {
		if got := byteHex(n); got != want {
			t.Errorf("byteHex(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestItoa(t *testing.T) {
	if itoa(123) != "123" {
		t.Error("itoa")
	}
}

// --- MLSx --------------------------------------------------------------------

func TestParseMLSxEntry(t *testing.T) {
	e, err := ParseMLSxEntry("size=4096;modify=20240101120000;type=dir;perm=el;unix.mode=0755;UNIQUE=AB; mydir\r\n")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if e.Pathname != "mydir" {
		t.Errorf("pathname = %q", e.Pathname)
	}
	if v := e.Facts["size"]; v.Kind != FactInt || v.Int != 4096 {
		t.Errorf("size = %+v", v)
	}
	if v := e.Facts["unix.mode"]; v.Int != 493 {
		t.Errorf("mode = %+v", v)
	}
	if v := e.Facts["type"]; v.Str != "dir" {
		t.Errorf("type = %+v", v)
	}
	// "unique" is CASE_DEPENDENT — value kept verbatim, name lower-cased.
	if v := e.Facts["unique"]; v.Str != "AB" {
		t.Errorf("unique = %+v", v)
	}
	if v := e.Facts["modify"]; v.Kind != FactTime || v.Time.Year != 2024 || v.Time.Hour != 12 {
		t.Errorf("modify = %+v", v)
	}
	if !e.IsDirectory() || e.IsFile() {
		t.Error("dir predicates")
	}
	if !reflect.DeepEqual(e.FactOrder, []string{"size", "modify", "type", "perm", "unix.mode", "unique"}) {
		t.Errorf("fact order = %v", e.FactOrder)
	}
}

func TestParseMLSxEntryFractionAndPerms(t *testing.T) {
	e, err := ParseMLSxEntry("type=file;modify=20240615133000.500;perm=radfw; my file.txt")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if e.Pathname != "my file.txt" {
		t.Errorf("pathname = %q", e.Pathname)
	}
	if e.Facts["modify"].Time.Nsec != 500000000 {
		t.Errorf("nsec = %d", e.Facts["modify"].Time.Nsec)
	}
	if !e.IsFile() || e.IsDirectory() {
		t.Error("file predicates")
	}
	for _, c := range []struct {
		f func() bool
		w bool
	}{
		{e.Readable, true}, {e.Appendable, true}, {e.Deletable, true},
		{e.Renamable, true}, {e.Writable, true},
		{e.Creatable, false}, {e.Enterable, false}, {e.Listable, false},
		{e.DirectoryMakable, false}, {e.Purgeable, false},
	} {
		if c.f() != c.w {
			t.Errorf("perm predicate mismatch want %v", c.w)
		}
	}
}

func TestParseMLSxEntryTypeVariants(t *testing.T) {
	for _, ty := range []string{"dir", "cdir", "pdir"} {
		e, _ := ParseMLSxEntry("type=" + ty + "; p")
		if !e.IsDirectory() {
			t.Errorf("%s should be directory", ty)
		}
	}
	// "xdir" must NOT match [cp]?dir.
	e, _ := ParseMLSxEntry("type=xdir; p")
	if e.IsDirectory() {
		t.Error("xdir is not a directory")
	}
	// Absent type/perm facts → predicates false.
	bare, _ := ParseMLSxEntry("size=1; p")
	if bare.IsDirectory() || bare.IsFile() || bare.Readable() {
		t.Error("absent facts should be false")
	}
	// A bare "\r" terminator is chomped before splitting (rubyChomp \r branch).
	cr, _ := ParseMLSxEntry("type=file; name\r")
	if cr.Pathname != "name" {
		t.Errorf("CR chomp pathname = %q", cr.Pathname)
	}
	// A bare "\n" terminator is chomped too.
	nl, _ := ParseMLSxEntry("type=file; name\n")
	if nl.Pathname != "name" {
		t.Errorf("LF chomp pathname = %q", nl.Pathname)
	}
}

func TestParseMLSxEntryErrors(t *testing.T) {
	// No space → proto error carrying the raw entry.
	if _, err := ParseMLSxEntry("size=1;type=file;"); !isKind(err, KindProto) {
		t.Fatalf("no space: %v", err)
	}
	// Invalid time-val propagates the parser's proto error.
	if _, err := ParseMLSxEntry("modify=notatime; p"); !isKind(err, KindProto) {
		t.Fatalf("bad time: %v", err)
	}
}

func TestParseTimeValTruncation(t *testing.T) {
	long := ""
	for i := 0; i < 120; i++ {
		long += "x"
	}
	_, err := parseTimeVal(long)
	var fe *FTPError
	if !errors.As(err, &fe) || fe.Kind != KindProto {
		t.Fatalf("kind: %v", err)
	}
	// Message truncated to 97 chars + "..." after the "invalid time-val: " prefix.
	want := "invalid time-val: " + long[:97] + "..."
	if fe.Message != want {
		t.Errorf("truncation msg = %q", fe.Message)
	}
}

func TestFractionToNsec(t *testing.T) {
	cases := map[string]int{
		"5":          500000000,
		"500":        500000000,
		"000000001":  1,
		"0000000001": 0, // finer than nsec → truncated to 0
		"123456789":  123456789,
	}
	for frac, want := range cases {
		if got := fractionToNsec(frac); got != want {
			t.Errorf("fractionToNsec(%q) = %d, want %d", frac, got, want)
		}
	}
}

func TestParseFactDefaultAndCaseFold(t *testing.T) {
	// media-type is CASE_INDEPENDENT → downcased.
	fv, _ := parseFact("media-type", "Text/Plain")
	if fv.Str != "text/plain" {
		t.Errorf("media-type fold = %q", fv.Str)
	}
	// An unknown fact is verbatim (CASE_DEPENDENT default).
	fv, _ = parseFact("vendor.x", "KeepCase")
	if fv.Str != "KeepCase" {
		t.Errorf("unknown verbatim = %q", fv.Str)
	}
	// decimal facts.
	fv, _ = parseFact("unix.owner", "1000")
	if fv.Int != 1000 {
		t.Errorf("owner = %d", fv.Int)
	}
}

// --- flow --------------------------------------------------------------------

func TestLoginNext(t *testing.T) {
	if s, err := LoginNext("331 need pass", false); err != nil || s != LoginSendPass {
		t.Errorf("user 3yz: %v %v", s, err)
	}
	if s, err := LoginNext("332 need acct", true); err != nil || s != LoginSendAcct {
		t.Errorf("pass 3yz: %v %v", s, err)
	}
	if s, err := LoginNext("230 ok", false); err != nil || s != LoginDone {
		t.Errorf("done 2yz: %v %v", s, err)
	}
	if s, err := LoginNext("530 bad", false); s != LoginDone || !isKind(err, KindReply) {
		t.Errorf("done non-2yz: %v %v", s, err)
	}
}

func TestAnonymousLogin(t *testing.T) {
	if pw, ok := AnonymousLogin("anonymous", false); !ok || pw != "anonymous@" {
		t.Errorf("anon: %q %v", pw, ok)
	}
	if _, ok := AnonymousLogin("anonymous", true); ok {
		t.Error("anon with passwd → no substitution")
	}
	if _, ok := AnonymousLogin("bob", false); ok {
		t.Error("named user → no substitution")
	}
}

func TestCheckDelete(t *testing.T) {
	if err := CheckDelete("250 deleted"); err != nil {
		t.Errorf("250: %v", err)
	}
	if err := CheckDelete("550 denied"); !isKind(err, KindPerm) {
		t.Errorf("5yz: %v", err)
	}
	if err := CheckDelete("450 busy"); !isKind(err, KindReply) {
		t.Errorf("other: %v", err)
	}
}

func TestCheckRenameFrom(t *testing.T) {
	if err := CheckRenameFrom("350 ready"); err != nil {
		t.Errorf("3yz: %v", err)
	}
	if err := CheckRenameFrom("550 no"); !isKind(err, KindReply) {
		t.Errorf("non-3yz: %v", err)
	}
}

func TestSizeSystMdtm(t *testing.T) {
	if n, err := SizeResult("213 1024"); err != nil || n != 1024 {
		t.Errorf("size: %d %v", n, err)
	}
	if _, err := SizeResult("500 bad"); !isKind(err, KindReply) {
		t.Errorf("size bad: %v", err)
	}
	if s, err := SystResult("215 UNIX Type: L8"); err != nil || s != "UNIX Type: L8" {
		t.Errorf("syst: %q %v", s, err)
	}
	if _, err := SystResult("500 bad"); !isKind(err, KindReply) {
		t.Errorf("syst bad: %v", err)
	}
	if s, ok := MdtmResult("213 20240101000000"); !ok || s != "20240101000000" {
		t.Errorf("mdtm: %q %v", s, ok)
	}
	if _, ok := MdtmResult("550 no"); ok {
		t.Error("mdtm bad should be false")
	}
}

func TestAbortAccepted(t *testing.T) {
	for _, c := range []string{"426 x", "226 x", "225 x"} {
		if !AbortAccepted(c) {
			t.Errorf("%q should be accepted", c)
		}
	}
	if AbortAccepted("500 x") {
		t.Error("500 not accepted")
	}
}

// isKind reports whether err is an *FTPError of the given kind.
func isKind(err error, k FTPErrorKind) bool {
	var fe *FTPError
	return errors.As(err, &fe) && fe.Kind == k
}
