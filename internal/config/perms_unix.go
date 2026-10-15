//go:build !windows

package config

import "os"

// restrictPermissions deja el directorio accesible solo para root.
func restrictPermissions(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		return err
	}
	return os.Chmod(dir, 0o750)
}

// GrantUserRead no es necesario en Linux: los informes se leen como root.
func GrantUserRead(string) error { return nil }
