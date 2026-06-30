package netftp

import (
	"errors"
	"strings"
)

// Command builders. Each returns the exact command line Net::FTP would hand to
// putline (without the trailing CRLF — see PutLine, which appends it and is the
// byte the host writes to the socket). The strings match MRI's command
// construction character-for-character.

// ErrLineHasCRLF is returned by PutLine when a command line contains a CR or LF,
// mirroring MRI's putline: `raise ArgumentError, "A line must not contain CR or
// LF"`.
var ErrLineHasCRLF = errors.New("A line must not contain CR or LF")

// PutLine validates a command line and appends CRLF, returning the bytes MRI's
// putline writes to the control socket. The actual write is the host's seam.
func PutLine(line string) (string, error) {
	if strings.ContainsAny(line, "\r\n") {
		return "", ErrLineHasCRLF
	}
	return line + CRLF, nil
}

// withArg appends " arg" to a verb when arg is non-empty, the idiom MRI uses for
// optional command arguments (e.g. `cmd = "#{cmd} #{dir}"`).
func withArg(verb, arg string) string {
	if arg == "" {
		return verb
	}
	return verb + " " + arg
}

// UserCommand builds the USER command (MRI: 'USER ' + user).
func UserCommand(user string) string { return "USER " + user }

// PassCommand builds the PASS command (MRI: 'PASS ' + passwd).
func PassCommand(passwd string) string { return "PASS " + passwd }

// AcctCommand builds the ACCT command (MRI: 'ACCT ' + acct).
func AcctCommand(acct string) string { return "ACCT " + acct }

// AnonymousPassword returns the password Net::FTP substitutes for an anonymous
// login when none is given: "anonymous@" (login: user == "anonymous" and passwd
// == nil → passwd = "anonymous@").
const AnonymousPassword = "anonymous@"

// TypeCommand builds the TYPE command for the current transfer mode, mirroring
// send_type_command: "TYPE I" when binary, "TYPE A" otherwise.
func TypeCommand(binary bool) string {
	if binary {
		return "TYPE I"
	}
	return "TYPE A"
}

// CwdCommand builds the CWD command (MRI chdir: "CWD #{dirname}").
func CwdCommand(dirname string) string { return "CWD " + dirname }

// CdupCommand is the CDUP command sent by chdir("..") before falling back to
// CWD on a 500 reply.
const CdupCommand = "CDUP"

// PwdCommand is the PWD command (pwd / getdir).
const PwdCommand = "PWD"

// NlstCommand builds the NLST command (MRI nlst: "NLST", optionally " #{dir}").
func NlstCommand(dir string) string { return withArg("NLST", dir) }

// ListCommand builds the LIST command, appending each argument separated by a
// space, mirroring MRI's list: `cmd = "LIST"; args.each { cmd = "#{cmd} #{arg}" }`.
func ListCommand(args ...string) string {
	cmd := "LIST"
	for _, a := range args {
		cmd += " " + a
	}
	return cmd
}

// MlsdCommand builds the MLSD command (MRI mlsd: "MLSD", optionally " #{pathname}").
func MlsdCommand(pathname string) string { return withArg("MLSD", pathname) }

// MlstCommand builds the MLST command (MRI mlst: "MLST", optionally " #{pathname}").
func MlstCommand(pathname string) string { return withArg("MLST", pathname) }

// RetrCommand builds the RETR command used by the binary/text get helpers.
func RetrCommand(filename string) string { return "RETR " + filename }

// StorCommand builds the STOR command used by the put helpers.
func StorCommand(filename string) string { return "STOR " + filename }

// DeleCommand builds the DELE command (MRI delete: "DELE #{filename}").
func DeleCommand(filename string) string { return "DELE " + filename }

// RnfrCommand builds the RNFR command (MRI rename: "RNFR #{fromname}").
func RnfrCommand(fromname string) string { return "RNFR " + fromname }

// RntoCommand builds the RNTO command (MRI rename: "RNTO #{toname}").
func RntoCommand(toname string) string { return "RNTO " + toname }

// MkdCommand builds the MKD command (MRI mkdir: "MKD #{dirname}").
func MkdCommand(dirname string) string { return "MKD " + dirname }

// RmdCommand builds the RMD command (MRI rmdir: "RMD #{dirname}").
func RmdCommand(dirname string) string { return "RMD " + dirname }

// SizeCommand builds the SIZE command (MRI size: "SIZE #{filename}").
func SizeCommand(filename string) string { return "SIZE " + filename }

// MdtmCommand builds the MDTM command (MRI mdtm: "MDTM #{filename}").
func MdtmCommand(filename string) string { return "MDTM " + filename }

// SystCommand is the SYST command (system / .system).
const SystCommand = "SYST"

// StatCommand builds the STAT command (MRI status: "STAT", optionally " #{pathname}").
func StatCommand(pathname string) string { return withArg("STAT", pathname) }

// FeatCommand is the FEAT command (features).
const FeatCommand = "FEAT"

// NoopCommand is the NOOP command (noop).
const NoopCommand = "NOOP"

// QuitCommand is the QUIT command (quit).
const QuitCommand = "QUIT"

// AborCommand is the ABOR command (abort); MRI sends it out-of-band.
const AborCommand = "ABOR"

// PasvCommand is the PASV command (set_socket / passive transfers, IPv4).
const PasvCommand = "PASV"

// EpsvCommand is the EPSV command (passive transfers, extended/IPv6).
const EpsvCommand = "EPSV"

// HelpCommand builds the HELP command (MRI help: "HELP", optionally " " + arg).
func HelpCommand(arg string) string { return withArg("HELP", arg) }

// SiteCommand builds the SITE command (MRI site: "SITE " + arg).
func SiteCommand(arg string) string { return "SITE " + arg }

// OptionCommand builds the OPTS command (MRI option: "OPTS #{name}",
// optionally " #{params}").
func OptionCommand(name, params string) string {
	cmd := "OPTS " + name
	if params != "" {
		cmd += " " + params
	}
	return cmd
}

// SendPort builds the PORT command for an active-mode IPv4 data connection,
// mirroring MRI sendport: "PORT " + (host.split(".") + port.divmod(256)).join(",").
// host is dotted-quad; the port's high and low bytes are appended.
func SendPort(host string, port int) string {
	hi := port / 256
	lo := port % 256
	parts := append(strings.Split(host, "."), itoa(hi), itoa(lo))
	return "PORT " + strings.Join(parts, ",")
}

// SendEPort builds the EPRT command for an active-mode IPv6 data connection,
// mirroring MRI sendport: sprintf("EPRT |2|%s|%d|", host, port).
func SendEPort(host string, port int) string {
	return "EPRT |2|" + host + "|" + itoa(port) + "|"
}
