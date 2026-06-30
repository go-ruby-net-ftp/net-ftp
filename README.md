<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-net-ftp/brand/main/social/go-ruby-net-ftp-net-ftp.png" alt="go-ruby-net-ftp/net-ftp" width="720"></p>

# net-ftp — go-ruby-net-ftp

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-net-ftp.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of the deterministic, interpreter-independent
core of Ruby's [`Net::FTP`](https://docs.ruby-lang.org/en/master/Net/FTP.html)** —
MRI's `net-ftp`. It builds the FTP command bytes a client sends on the control
connection, parses the 3-digit (optionally multiline) replies a server returns,
extracts the data-connection address from `PASV` / `EPSV` responses, and parses
`MLSD` / `MLST` entries and quoted pathnames — everything `Net::FTP` does that is
**pure computation over bytes**, with no I/O and **no Ruby runtime**.

It is the FTP protocol codec for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module — a sibling of
[go-ruby-net-smtp](https://github.com/go-ruby-net-smtp/net-smtp) and
[go-ruby-regexp](https://github.com/go-ruby-regexp/regexp).

> **What it is — and isn't.** Constructing command lines, classifying reply codes,
> extracting a `PASV`/`EPSV` host:port, and parsing the `MLSx` fact grammar are
> fully deterministic and need **no interpreter**, so they live here as pure Go.
> The **control and data sockets** — connecting, reading, writing, TLS — are the
> host's job. They are **seams**: this library never opens a socket. The host
> feeds raw reply lines in (via a `LineReader`) and writes the command bytes this
> library produces out.

## Features

Faithful port of `Net::FTP`'s pure-compute core, validated against the `ruby`
binary on every supported platform:

- **Command builders** for `USER`/`PASS`/`ACCT`/`CWD`/`CDUP`/`PWD`/`TYPE`/`PASV`/
  `EPSV`/`PORT`/`EPRT`/`LIST`/`NLST`/`MLSD`/`MLST`/`RETR`/`STOR`/`DELE`/`RNFR`/
  `RNTO`/`MKD`/`RMD`/`SIZE`/`MDTM`/`SYST`/`STAT`/`FEAT`/`OPTS`/`SITE`/`HELP`/
  `NOOP`/`ABOR`/`QUIT` — byte-for-byte with MRI's construction, plus `PutLine`
  (CRLF append + CR/LF rejection) and `Sanitize` (PASS masking).
- **Reply parsing** — `GetMultiline` assembles single- and multiline (`220-…` /
  `220 …`) replies; `ClassifyReply` maps the leading digit to success / `Temp` /
  `Perm` / `Proto`, exactly as `getresp` does; `VoidResp` enforces the `2yz`
  rule with MRI's ordering; `ReplyBody` is `get_body`.
- **`PASV` / `EPSV` address extraction** — `Parse227` (`227 (h1,h2,h3,h4,p1,p2)`
  → `host:port`, honouring `use_pasv_ip`), `Parse229` (`229 (|||port|)`), and the
  IPv6 `PasvIPv6Host` helper, with `Parse257`'s quoted-pathname (`""`-collapsing)
  decode.
- **`MLSD` / `MLST` parsing** — `ParseMLSxEntry` reproduces `parse_mlsx_entry`
  and the full `FACT_PARSERS` table (decimal / octal / time / case-folded /
  verbatim), returning an `MLSxEntry` with the perm-bit predicates
  (`IsFile`/`IsDirectory`/`Readable`/`Writable`/…).
- **The `Net::FTPError` family** — `FTPReplyError` / `FTPTempError` /
  `FTPPermError` / `FTPProtoError` / `FTPConnectionError`, keyed by reply code and
  carrying MRI's message text, each with the Ruby class name the host re-raises.
- **CGO=0**, no dependencies beyond the standard library, and **pure-Go on all
  six 64-bit Go targets** (amd64, arm64, riscv64, loong64, ppc64le, s390x).

## The socket seams

The host supplies two things; everything else is computed here:

- **Reading** — a `LineReader` (`func() (string, error)`) that yields successive
  raw lines from the control connection. `GetMultiline` / `GetResp` / `VoidResp`
  call it; an error it returns stands in for MRI's `EOFError` / read failure.
- **Writing** — the host writes the bytes a command builder returns (terminated
  via `PutLine`). The data connection (active `PORT`/`EPRT` or passive
  `PASV`/`EPSV`) is dialed by the host using the `host`/`port` this library
  extracts from the reply.

## Tests & coverage

```sh
GOWORK=off go test -race -cover ./...
```

The suite is **100% statement coverage**. The deterministic, Ruby-free tests
cover every branch on their own (so the Windows and qemu cross-arch CI lanes hold
the gate); where the `ruby` binary is present, the `oracle_test.go` suite
additionally pins command bytes, reply parse, `PASV`/`EPSV` extraction, and
`MLSx` parsing to live `Net::FTP` output.

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright (c) 2026, the
go-ruby-net-ftp/net-ftp authors.
