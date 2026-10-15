//go:build windows

package report

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVT activa las secuencias ANSI en la consola de Windows 10+.
func enableVT(f *os.File) bool {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
