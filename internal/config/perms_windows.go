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
//
// Un usuario sin privilegios puede crear carpetas en %ProgramData%: si
// creara C:\ProgramData\Bastion antes de la instalación, seguiría siendo
// su propietario (y el propietario siempre puede cambiar los permisos) y
// podría dejar un config.yaml que apuntara las actualizaciones a un espejo
// suyo. Por eso, además de fijar los permisos de la carpeta, se pasa la
// propiedad de todo a Administradores y se restablecen los permisos de su
// contenido para que solo hereden los de la carpeta.
func restrictPermissions(dir string) error {
	if err := icacls(dir, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"); err != nil {
		return err
	}
	if err := icacls(dir, "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "/Q"); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return err
	}
	return icacls(filepath.Join(dir, "*"), "/reset", "/T", "/C", "/Q")
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
