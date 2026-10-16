//go:build !windows

package schedule

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// SafeExecutable comprueba que nadie sin privilegios pueda sustituir el
// ejecutable que lanzará la tarea como root: el fichero y todas las
// carpetas hasta / deben ser de root y sin permiso de escritura para el
// grupo ni para otros.
func SafeExecutable(exe string) error {
	p, err := filepath.Abs(exe)
	if err != nil {
		return err
	}
	for {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("no se pueden leer el propietario y los permisos de %s", p)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s no pertenece a root: otro usuario podría sustituir el ejecutable", p)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s tiene permiso de escritura para el grupo u otros usuarios (%04o)", p, fi.Mode().Perm())
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}
