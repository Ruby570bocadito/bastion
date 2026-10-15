//go:build !linux && !windows

package surface

import (
	"context"
	"errors"
)

// Collect no está disponible en este sistema.
func Collect(context.Context) (Inventory, error) {
	return Inventory{}, errors.New("el análisis de superficie solo está disponible en Linux y Windows")
}
