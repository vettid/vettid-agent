package mcp

import (
	"unicode/utf8"
)

// The JSON of a tool result that holds item values (leash.request_secret,
// and leash.execute_action's HMAC) is written by hand into one byte
// slice sized up front, never through Go strings or encoding/json's
// internal buffers, so that the copy this process makes can be zeroed
// once it is written to standard output (as far as Go allows: the
// runtime may have copied memory, and what the MCP client does with the
// result is outside this process).

// appendQuoted appends b as a JSON string: `"` and `\` escaped, control
// characters as \n, \r, \t or \u00XX, U+2028 and U+2029 escaped, and
// each byte of an invalid UTF-8 sequence replaced by \ufffd.
func appendQuoted(dst, b []byte) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(b); {
		c := b[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				dst = append(dst, '\\', c)
			case c == '\n':
				dst = append(dst, '\\', 'n')
			case c == '\r':
				dst = append(dst, '\\', 'r')
			case c == '\t':
				dst = append(dst, '\\', 't')
			case c < 0x20 || c == 0x7f:
				dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			default:
				dst = append(dst, c)
			}
			i++
			continue
		}
		r, n := utf8.DecodeRune(b[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			dst = append(dst, "\\ufffd"...)
		case r == '\u2028' || r == '\u2029':
			dst = append(dst, '\\', 'u', '2', '0', '2', hex[r&0xf])
		default:
			dst = append(dst, b[i:i+n]...)
		}
		i += n
	}
	return append(dst, '"')
}

// quotedBound is the most bytes appendQuoted appends for n input bytes.
func quotedBound(n int) int { return 6*n + 2 }

// appendCompact appends raw, a valid JSON value (as encoding/json
// accepted it), without the whitespace between tokens, so that it fits
// on one line of the stdio transport. Inside strings, each byte of an
// invalid UTF-8 sequence is replaced by \ufffd and U+2028 and U+2029
// are escaped; everything else is copied as it is.
func appendCompact(dst, raw []byte) []byte {
	inString := false
	for i := 0; i < len(raw); {
		c := raw[i]
		if !inString {
			switch c {
			case ' ', '\t', '\n', '\r':
			case '"':
				inString = true
				dst = append(dst, c)
			default:
				dst = append(dst, c)
			}
			i++
			continue
		}
		switch {
		case c == '\\' && i+1 < len(raw):
			dst = append(dst, c, raw[i+1])
			i += 2
		case c == '"':
			inString = false
			dst = append(dst, c)
			i++
		case c < utf8.RuneSelf:
			dst = append(dst, c)
			i++
		default:
			r, n := utf8.DecodeRune(raw[i:])
			switch {
			case r == utf8.RuneError && n == 1:
				dst = append(dst, "\\ufffd"...)
			case r == '\u2028' || r == '\u2029':
				dst = append(dst, '\\', 'u', '2', '0', '2', "0123456789abcdef"[r&0xf])
			default:
				dst = append(dst, raw[i:i+n]...)
			}
			i += n
		}
	}
	return dst
}

// compactBound is the most bytes appendCompact appends for n input
// bytes.
func compactBound(n int) int { return 6 * n }
