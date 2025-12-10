package sanitize

import (
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
)

// String sanitizes a string by replacing non-printable characters with hex encoding
// Non-printable characters are encoded as <hex> (e.g., newline becomes <0a>)
func String(data string) string {
	// Fast path: check if sanitization is needed
	needsSanitization := false
	for _, r := range data {
		if !strconv.IsPrint(r) {
			needsSanitization = true
			break
		}
	}

	if !needsSanitization {
		return data
	}

	// Pre-allocate builder for efficiency
	var builder strings.Builder
	builder.Grow(len(data))

	for _, r := range data {
		if strconv.IsPrint(r) {
			builder.WriteRune(r)
		} else {
			// Encode non-printable rune as <hex>
			var runeBytes [utf8.UTFMax]byte
			n := utf8.EncodeRune(runeBytes[:], r)
			builder.WriteByte('<')
			builder.WriteString(hex.EncodeToString(runeBytes[:n]))
			builder.WriteByte('>')
		}
	}

	return builder.String()
}

// Bytes sanitizes a byte slice by converting to string and sanitizing
func Bytes(data []byte) []byte {
	return []byte(String(string(data)))
}

// Rune sanitizes a single rune, returning its string representation
func Rune(r rune) string {
	if strconv.IsPrint(r) {
		return string(r)
	}

	var runeBytes [utf8.UTFMax]byte
	n := utf8.EncodeRune(runeBytes[:], r)
	return "<" + hex.EncodeToString(runeBytes[:n]) + ">"
}

// IsSafe checks if a string contains only printable characters
func IsSafe(data string) bool {
	for _, r := range data {
		if !strconv.IsPrint(r) {
			return false
		}
	}
	return true
}