//go:build windows

package cli

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// relaunchElevated vuelve a lanzar Bastion con los argumentos dados en una
// ventana de administrador (aviso de UAC). No espera a que termine.
func relaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = windows.EscapeArg(a)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	err = windows.ShellExecute(0, verb, file, params, nil, windows.SW_SHOWNORMAL)
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return errors.New("se canceló el aviso de Windows: no se ha actualizado nada")
	}
	return err
}

func canElevate() bool { return true }
