package report

import (
	"os"
	"runtime"
	"strings"
)

// Style aplica colores ANSI solo si la salida es una terminal y el usuario
// no ha pedido lo contrario (NO_COLOR, --no-color).
type Style struct{ on bool }

// NewStyle detecta si f admite colores.
func NewStyle(f *os.File, noColor bool) Style {
	if noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return Style{}
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return Style{}
	}
	return Style{on: enableVT(f)}
}

// Enabled indica si se emiten colores.
func (s Style) Enabled() bool { return s.on }

func (s Style) wrap(code, text string) string {
	if !s.on || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s Style) Bold(t string) string    { return s.wrap("1", t) }
func (s Style) Dim(t string) string     { return s.wrap("2", t) }
func (s Style) Red(t string) string     { return s.wrap("31", t) }
func (s Style) Green(t string) string   { return s.wrap("32", t) }
func (s Style) Yellow(t string) string  { return s.wrap("33", t) }
func (s Style) Blue(t string) string    { return s.wrap("34", t) }
func (s Style) Magenta(t string) string { return s.wrap("35", t) }
func (s Style) Cyan(t string) string    { return s.wrap("36", t) }
func (s Style) BoldRed(t string) string { return s.wrap("1;31", t) }

// pad rellena a n columnas contando runas (no bytes).
func pad(s string, n int) string {
	l := len([]rune(s))
	if l >= n {
		return s
	}
	return s + strings.Repeat(" ", n-l)
}

// legacyConsole es true en la consola clásica de Windows (conhost), cuya
// fuente por defecto no tiene algunos símbolos Unicode. Windows Terminal
// (WT_SESSION) y las terminales de Linux sí los muestran.
var legacyConsole = runtime.GOOS == "windows" && os.Getenv("WT_SESSION") == "" && os.Getenv("TERM_PROGRAM") == ""

var fallbackSymbols = map[string]string{
	"✓": "√", "✗": "×", "▲": "■", "⚠": "!", "○": "o", "→": "->", "↑": "^", "↓": "v", "⊘": "-", "◇": "*",
}

// Sym devuelve el símbolo o su alternativa para la consola clásica de Windows.
func Sym(s string) string {
	if legacyConsole {
		if f, ok := fallbackSymbols[s]; ok {
			return f
		}
	}
	return s
}
