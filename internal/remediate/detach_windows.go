//go:build windows

package remediate

import (
	"os/exec"
	"syscall"
)

const detachedProcess = 0x00000008

// detach crea el proceso sin consola y en su propio grupo, para que
// sobreviva al cierre de la ventana o a la desconexión de RDP.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP}
}
