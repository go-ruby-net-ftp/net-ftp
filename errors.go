package netftp

// The Net::FTP exception family. MRI defines (net/ftp.rb):
//
//	class FTPError < StandardError; end
//	class FTPReplyError < FTPError; end
//	class FTPTempError  < FTPError; end
//	class FTPPermError  < FTPError; end
//	class FTPProtoError < FTPError; end
//	class FTPConnectionError < FTPError; end
//
// Each carries the offending reply text as its message, exactly as MRI raises
// it (e.g. `raise FTPPermError, @last_response`). The host maps these to the
// corresponding Ruby exception classes.

// FTPError is the base of the Net::FTP error family (Net::FTPError).
type FTPError struct {
	// Kind names the concrete Net::FTP subclass this error represents.
	Kind FTPErrorKind
	// Message is the reply (or other) text MRI passes to `raise`.
	Message string
}

// FTPErrorKind enumerates the concrete Net::FTP error subclasses.
type FTPErrorKind int

const (
	// KindReply is Net::FTPReplyError — an unexpected reply code.
	KindReply FTPErrorKind = iota
	// KindTemp is Net::FTPTempError — a 4yz transient negative reply.
	KindTemp
	// KindPerm is Net::FTPPermError — a 5yz permanent negative reply.
	KindPerm
	// KindProto is Net::FTPProtoError — a reply that is not 1/2/3/4/5yz, or
	// otherwise malformed.
	KindProto
	// KindConnection is Net::FTPConnectionError — a control-connection failure.
	KindConnection
)

// className is the Ruby class name for each kind, so the host can re-raise the
// matching exception.
func (k FTPErrorKind) className() string {
	switch k {
	case KindReply:
		return "Net::FTPReplyError"
	case KindTemp:
		return "Net::FTPTempError"
	case KindPerm:
		return "Net::FTPPermError"
	case KindProto:
		return "Net::FTPProtoError"
	case KindConnection:
		return "Net::FTPConnectionError"
	default:
		return "Net::FTPError"
	}
}

// ClassName returns the Ruby exception class name (e.g. "Net::FTPPermError")
// the host should raise for this error.
func (e *FTPError) ClassName() string { return e.Kind.className() }

// Error implements the error interface, returning the reply text MRI uses as
// the exception message.
func (e *FTPError) Error() string { return e.Message }

func replyErr(msg string) *FTPError { return &FTPError{Kind: KindReply, Message: msg} }
func tempErr(msg string) *FTPError  { return &FTPError{Kind: KindTemp, Message: msg} }
func permErr(msg string) *FTPError  { return &FTPError{Kind: KindPerm, Message: msg} }
func protoErr(msg string) *FTPError { return &FTPError{Kind: KindProto, Message: msg} }
