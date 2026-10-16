//go:build windows

package cli

import "golang.org/x/sys/windows"

// discardPendingInput descarta lo que ya esté en el búfer de la consola
// antes de hacer una pregunta. Al pegar varios comandos a la vez, el salto
// de línea sobrante llegaba como respuesta vacía y cancelaba sin preguntar.
func discardPendingInput() {
	if h, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE); err == nil {
		_ = windows.FlushConsoleInputBuffer(h)
	}
}
