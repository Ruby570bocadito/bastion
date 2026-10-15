// Package version expone la versión del binario. Los valores se inyectan en
// tiempo de compilación con -ldflags (ver .goreleaser.yaml y Makefile).
package version

import "fmt"

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
	// Repo es el repositorio de GitHub (owner/nombre) del que se descargan
	// las actualizaciones. Se puede sobrescribir con BASTION_REPO.
	Repo = "Ruby570bocadito/bastion"
)

// String devuelve la versión completa en una línea.
func String() string {
	return fmt.Sprintf("bastion %s (commit %s, %s)", Version, Commit, Date)
}
