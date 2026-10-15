//go:build !windows

package remediate

import (
	"os/exec"
	"syscall"
)

// detach desvincula el proceso de la sesión actual (sobrevive al cierre de
// la terminal o de la conexión SSH).
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
