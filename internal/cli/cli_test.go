package cli

import "testing"

func TestIsYes(t *testing.T) {
	for _, a := range []string{"s", "S\r\n", "si", "sí", "s\xa1", "Sí\n", "y", "yes", "  s  "} {
		if !isYes(a) {
			t.Errorf("%q debería confirmar", a)
		}
	}
	for _, a := range []string{"", "\r\n", "n", "no", "N", "cancelar", "x", "salir", "sin cambios", "sx"} {
		if isYes(a) {
			t.Errorf("%q no debería confirmar", a)
		}
	}
}
