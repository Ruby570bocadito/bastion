package schedule

import "context"

// Scheduler crea, quita y describe la tarea programada.
type Scheduler interface {
	Enable(ctx context.Context, exe, at string) (Status, error)
	Disable(ctx context.Context) error
	Get(ctx context.Context) (Status, error)
}
