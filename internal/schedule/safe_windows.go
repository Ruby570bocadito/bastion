//go:build windows

package schedule

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SafeExecutable comprueba que el ejecutable que lanzará la tarea como
// SYSTEM esté en una carpeta que solo pueden modificar los administradores
// (Program Files o la carpeta de Windows). Desde Descargas o el escritorio,
// cualquier usuario podría sustituirlo y obtener privilegios de SYSTEM.
func SafeExecutable(exe string) error {
	p, err := filepath.Abs(exe)
	if err != nil {
		return err
	}
	low := strings.ToLower(p)
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "SystemRoot"} {
		dir := os.Getenv(env)
		if dir == "" {
			continue
		}
		if prefix := strings.ToLower(strings.TrimRight(dir, `\`)) + `\`; strings.HasPrefix(low, prefix) {
			return nil
		}
	}
	return fmt.Errorf("%s no está en Program Files: la tarea se ejecuta como SYSTEM y cualquier usuario que pueda escribir en esa carpeta podría sustituir el ejecutable", p)
}
