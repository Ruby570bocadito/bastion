//go:build linux

package cli

import (
	"os"

	"golang.org/x/sys/unix"
)

// discardPendingInput descarta la entrada pendiente de la terminal antes de
// hacer una pregunta (p. ej. líneas pegadas de más).
func discardPendingInput() {
	_ = unix.IoctlSetInt(int(os.Stdin.Fd()), unix.TCFLSH, unix.TCIFLUSH)
}
