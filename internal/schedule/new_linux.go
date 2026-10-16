//go:build linux

package schedule

// New devuelve el planificador del sistema.
func New() (Scheduler, error) { return newUnix(), nil }
