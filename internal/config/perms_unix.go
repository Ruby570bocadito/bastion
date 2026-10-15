//go:build !windows

package config

import "os"

// restrictPermissions deja el directorio accesible solo para root.
func restrictPermissions(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return os.Chmod(dir, 0o750)
}
