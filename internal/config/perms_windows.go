//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
)

// restrictPermissions limita el directorio a Administradores y SYSTEM.
// Se usan SIDs para que funcione con Windows en cualquier idioma.
func restrictPermissions(dir string) error {
	icacls := filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe")
	return exec.Command(icacls, dir, "/inheritance:r",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "/Q").Run()
}
