//go:build windows

package probes

import (
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func init() {
	decodeLegacy = func(b []byte) string {
		if len(b) == 0 {
			return ""
		}
		n, err := windows.MultiByteToWideChar(windows.GetACP(), 0, &b[0], int32(len(b)), nil, 0)
		if err != nil || n <= 0 {
			return string(b)
		}
		u := make([]uint16, n)
		if _, err := windows.MultiByteToWideChar(windows.GetACP(), 0, &b[0], int32(len(b)), &u[0], n); err != nil {
			return string(b)
		}
		return string(utf16.Decode(u))
	}
}
