package netftp

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// Differential tests against the live MRI `ruby -rnet/ftp` binary. They pin this
// package's command bytes, reply parse, PASV/EPSV extraction, and MLSx parsing
// to Net::FTP's own behaviour. They self-skip on Windows (the org's ruby-free
// lane) and wherever `ruby` is absent (qemu arch lanes), so the deterministic
// tests alone hold the 100% gate; where ruby is installed, these run.

// ruby runs a Ruby snippet and returns its trimmed stdout, skipping the test if
// ruby is unavailable or Net::FTP cannot be required.
func ruby(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("oracle tests skip on Windows (ruby-free lane)")
	}
	if _, err := exec.LookPath("ruby"); err != nil {
		t.Skip("ruby not installed; skipping MRI oracle")
	}
	out, err := exec.Command("ruby", "-rnet/ftp", "-e", script).CombinedOutput()
	if err != nil {
		t.Skipf("ruby net/ftp unavailable (%v): %s", err, out)
	}
	return strings.TrimRight(string(out), "\n")
}

// helper Ruby preamble exposing Net::FTP's private parsers on a socket-free
// subclass.
const probe = `
class P < Net::FTP
  def initialize(use_pasv_ip = true); @use_pasv_ip = use_pasv_ip; end
  public :parse227, :parse229, :parse257, :parse_mlsx_entry,
         :parse_pasv_port, :parse_pasv_ipv4_host, :parse_pasv_ipv6_host,
         :sanitize, :get_body
end
`

func TestOracleSanitize(t *testing.T) {
	for _, in := range []string{"PASS hunter2", "USER bob", "PASS ", "pass mixedCase"} {
		want := ruby(t, probe+`print P.new.sanitize(`+rubyStr(in)+`)`)
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want MRI %q", in, got, want)
		}
	}
}

func TestOracleGetBody(t *testing.T) {
	for _, in := range []string{"215 UNIX Type: L8", "213 1024", "21X file"} {
		want := ruby(t, probe+`print P.new.get_body(`+rubyStr(in)+`).to_s`)
		got, _ := ReplyBody(in)
		if got != want {
			t.Errorf("ReplyBody(%q) = %q, want MRI %q", in, got, want)
		}
	}
}

func TestOracleParse227(t *testing.T) {
	resps := []string{
		"227 Entering Passive Mode (192,168,0,1,7,138)",
		"227 PASV ok (10,0,0,5,200,21)",
	}
	for _, resp := range resps {
		want := ruby(t, probe+`h, p = P.new(true).parse227(`+rubyStr(resp)+`); print "#{h} #{p}"`)
		host, port, err := Parse227(resp, true, "")
		got := host + " " + itoa(port)
		if err != nil || got != want {
			t.Errorf("Parse227(%q) = %q (%v), want MRI %q", resp, got, err, want)
		}
	}
}

func TestOracleParse229(t *testing.T) {
	// EPSV returns the control socket's address for the host; with no socket MRI
	// raises, so we compare only the port (the part this package computes).
	for _, resp := range []string{
		"229 Entering Extended Passive Mode (|||6446|)",
		"229 EPSV ok (!!!21!)",
	} {
		want := ruby(t, probe+`
m = /\((?<d>[!-~])\k<d>\k<d>(?<port>\d+)\k<d>\)/.match(`+rubyStr(resp)+`)
print m["port"].to_i`)
		_, port, err := Parse229(resp, "x")
		if err != nil || itoa(port) != want {
			t.Errorf("Parse229(%q) port = %d (%v), want MRI %s", resp, port, err, want)
		}
	}
}

func TestOracleParse257(t *testing.T) {
	for _, resp := range []string{
		`257 "/home/user" created`,
		`257 "/a""b" is the current directory`,
		`257 created without quotes`,
	} {
		want := ruby(t, probe+`print P.new.parse257(`+rubyStr(resp)+`)`)
		got, err := Parse257(resp)
		if err != nil || got != want {
			t.Errorf("Parse257(%q) = %q (%v), want MRI %q", resp, got, err, want)
		}
	}
}

func TestOraclePasvPortAndHosts(t *testing.T) {
	want := ruby(t, probe+`print P.new.parse_pasv_port("7,138")`)
	if itoa(pasvPort("7,138")) != want {
		t.Errorf("pasvPort = %d, want %s", pasvPort("7,138"), want)
	}
	want = ruby(t, probe+`print P.new.parse_pasv_ipv4_host("192,168,0,1")`)
	if pasvIPv4Host("192,168,0,1") != want {
		t.Errorf("pasvIPv4Host = %q, want %q", pasvIPv4Host("192,168,0,1"), want)
	}
	v6 := "16,1,16,2,16,3,16,4,16,5,16,6,16,7,16,8"
	want = ruby(t, probe+`print P.new.parse_pasv_ipv6_host(`+rubyStr(v6)+`)`)
	if PasvIPv6Host(v6) != want {
		t.Errorf("PasvIPv6Host = %q, want %q", PasvIPv6Host(v6), want)
	}
}

func TestOracleMLSxEntry(t *testing.T) {
	entries := []string{
		"size=4096;modify=20240101120000;type=dir;perm=el;unix.mode=0755; mydir",
		"size=1024;type=file;modify=20240615133000.500;perm=radfw; my file.txt",
		"Type=CDIR;Modify=20230101000000;UNIQUE=AB; .",
	}
	for _, e := range entries {
		// Compare pathname, the sorted fact-name set, and each fact rendered as a
		// canonical string, so Time/Integer/String values all line up with MRI.
		want := ruby(t, probe+`
def render(v)
  case v
  when Time then v.utc.strftime("%Y%m%d%H%M%S") + (v.nsec.zero? ? "" : ".#{v.nsec}")
  else v.to_s
  end
end
ent = P.new.parse_mlsx_entry(`+rubyStr(e)+`)
keys = ent.facts.keys.sort
parts = keys.map { |k| "#{k}=#{render(ent.facts[k])}" }
print "#{ent.pathname}|#{parts.join(",")}"`)
		got, err := ParseMLSxEntry(e)
		if err != nil {
			t.Fatalf("ParseMLSxEntry(%q): %v", e, err)
		}
		if rendered := renderEntry(got); rendered != want {
			t.Errorf("ParseMLSxEntry(%q)\n got = %q\nwant = %q", e, rendered, want)
		}
	}
}

// renderEntry renders a parsed entry in the same canonical "pathname|k=v,k=v"
// form the Ruby oracle produces (facts sorted by name; Time as
// YYYYMMDDhhmmss[.nsec]).
func renderEntry(e MLSxEntry) string {
	keys := make([]string, 0, len(e.Facts))
	for k := range e.Facts {
		keys = append(keys, k)
	}
	sortStrings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + renderFact(e.Facts[k])
	}
	return e.Pathname + "|" + strings.Join(parts, ",")
}

func renderFact(v FactValue) string {
	switch v.Kind {
	case FactInt:
		return itoa(v.Int)
	case FactTime:
		s := pad4(v.Time.Year) + pad2(v.Time.Month) + pad2(v.Time.Day) +
			pad2(v.Time.Hour) + pad2(v.Time.Min) + pad2(v.Time.Sec)
		if v.Time.Nsec != 0 {
			s += "." + itoa(v.Time.Nsec)
		}
		return s
	default:
		return v.Str
	}
}

func pad2(n int) string {
	s := itoa(n)
	if len(s) < 2 {
		return "0" + s
	}
	return s
}

func pad4(n int) string {
	s := itoa(n)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

// rubyStr renders a Go string as a Ruby double-quoted literal for embedding in a
// snippet. Only the characters the test inputs use need escaping.
func rubyStr(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// sortStrings is a tiny insertion sort (avoids importing sort just for tests).
func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}
