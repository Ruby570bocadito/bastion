//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func icacls(args ...string) error {
	return exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), args...).Run()
}

// restrictPermissions limita el directorio a Administradores y SYSTEM.
// Se usan SIDs para que funcione con Windows en cualquier idioma.
func restrictPermissions(dir string) error {
	return icacls(dir, "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "/Q")
}

// GrantUserRead da permiso de lectura sobre dir al usuario que ejecuta
// Bastion. Con UAC, el navegador y el Explorador se ejecutan sin elevar y el
// grupo Administradores no les sirve: sin este permiso el usuario no podría
// abrir sus propios informes.
func GrantUserRead(dir string) error {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := tu.User.Sid.String()
	if sid == "S-1-5-18" { // SYSTEM (tarea programada o servicio): nada que hacer
		return nil
	}
	return icacls(dir, "/grant", "*"+sid+":(OI)(CI)RX", "/Q")
}
