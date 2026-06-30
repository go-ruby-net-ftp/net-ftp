// Package netftp is a pure-Go (CGO=0) reimplementation of the deterministic,
// interpreter-independent core of Ruby's Net::FTP (MRI's net-ftp 0.3.9).
//
// It is the protocol codec: it builds the FTP command bytes a client sends on
// the control connection, parses the 3-digit (optionally multiline) replies a
// server returns, extracts the data-connection address from PASV / EPSV
// responses, and parses MLSD / MLST entries and quoted pathnames — everything
// Net::FTP does that is pure computation over bytes, with no I/O.
//
// The control and data sockets — connecting, reading, writing, TLS — are the
// host's job. They are SEAMS: this package never opens a socket. The host
// (go-embedded-ruby's rbgo) feeds reply text in and writes the command bytes
// this package produces out. Every observable byte — command line, reply
// classification, PASV/EPSV host:port, MLSx facts — matches MRI's net-ftp
// byte-for-byte, validated against the `ruby -rnet/ftp` binary.
package netftp

// CRLF is the line terminator Net::FTP appends to every control-connection
// command (Net::FTP::CRLF).
const CRLF = "\r\n"
