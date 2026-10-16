//go:build !linux && !windows

package schedule

// New devuelve el planificador del sistema.
func New() (Scheduler, error) { return nil, ErrUnsupported }
