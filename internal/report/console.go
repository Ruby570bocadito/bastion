// Package report genera los informes de un escaneo: consola, JSON y HTML.
package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/engine"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// SeverityLabel traduce la severidad para mostrarla.
func SeverityLabel(s rule.Severity) string {
	return map[rule.Severity]string{
		rule.SevCritical: "CRÍTICO", rule.SevHigh: "ALTO", rule.SevMedium: "MEDIO",
		rule.SevLow: "BAJO", rule.SevInfo: "INFO",
	}[s]
}

// ConsoleOptions controla el detalle de la salida de consola.
type ConsoleOptions struct {
	ShowAll bool // incluir superados y no aplicables
	Style   Style
}

// Console escribe el resumen del escaneo para humanos.
func Console(w io.Writer, rep *engine.Report, o ConsoleOptions) {
	s := o.Style
	line := s.Dim(strings.Repeat("─", 72))
	host := rep.Host

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s  %s %s\n", s.Bold(s.Cyan(Sym("▲")+" BASTION")), s.Dim("·"), s.Dim("auditoría de hardening  "+rep.Tool.Version))
	fmt.Fprintln(w, "  "+line)

	desc := []string{host.Name}
	if host.Kernel != "" {
		desc = append(desc, "kernel "+host.Kernel)
	}
	if host.Build != "" {
		desc = append(desc, "build "+host.Build)
	}
	desc = append(desc, host.Arch)
	fmt.Fprintf(w, "  %s %s %s\n", s.Dim(pad("Equipo", 9)), s.Bold(host.Hostname), s.Dim("· "+strings.Join(desc, " · ")))
	role := map[string]string{"workstation": "estación de trabajo", "server": "servidor", "dc": "controlador de dominio"}[host.Role]
	if role != "" {
		extra := role
		if host.DomainJoined {
			extra += " · dominio " + host.Domain
		}
		if host.Container {
			extra += " · contenedor"
		}
		fmt.Fprintf(w, "  %s %s\n", s.Dim(pad("Rol", 9)), extra)
	}
	if rep.Profile != nil {
		fmt.Fprintf(w, "  %s %s %s\n", s.Dim(pad("Perfil", 9)), rep.Profile.Name, s.Dim("("+rep.Profile.ID+")"))
	}
	fmt.Fprintf(w, "  %s %d controles en %s %s\n", s.Dim(pad("Escaneo", 9)), rep.Score.Total,
		fmtDuration(time.Duration(rep.DurationMs)*time.Millisecond), s.Dim("· "+rep.FinishedAt.Local().Format("2006-01-02 15:04")))

	sc := rep.Score
	if sc.Skipped > 0 {
		fmt.Fprintln(w)
		who := "administrador"
		if host.Family != "windows" {
			who = "root"
		}
		fmt.Fprintf(w, "  %s %s\n", s.Yellow(Sym("⚠")), s.Yellow(fmt.Sprintf("Sin privilegios de %s: %s no se %s podido evaluar.",
			who, plural(sc.Skipped, "control", "controles"), map[bool]string{true: "ha", false: "han"}[sc.Skipped == 1])))
		fmt.Fprintf(w, "    %s\n", s.Dim(AdminHint(host.Family)))
	}

	// Puntuación
	fmt.Fprintln(w)
	gradeColor := scoreColor(s, sc.Value)
	partial := ""
	switch {
	case sc.Skipped > 0 && sc.Errors > 0:
		partial = s.Dim(" (parcial: hay controles sin evaluar y errores)")
	case sc.Skipped > 0:
		partial = s.Dim(" (parcial: hay controles sin evaluar)")
	case sc.Errors > 0:
		partial = s.Dim(" (parcial: hay errores)")
	}
	fmt.Fprintf(w, "  %s  %s %s  %s%s\n", s.Bold("POSTURA"), gradeColor(s.Bold(fmt.Sprintf("%3d/100", sc.Value))),
		gradeColor(s.Bold(sc.Grade)), bar(s, sc.Value, 36), partial)
	counts := []string{
		s.Green(fmt.Sprintf(Sym("✓")+" %d superados", sc.Passed)),
		s.Red(fmt.Sprintf(Sym("✗")+" %d fallidos", sc.Failed)),
	}
	if sc.Errors > 0 {
		counts = append(counts, s.Yellow(fmt.Sprintf("! %d errores", sc.Errors)))
	}
	if sc.Skipped > 0 {
		counts = append(counts, s.Yellow(fmt.Sprintf(Sym("⊘")+" %d sin evaluar", sc.Skipped)))
	}
	counts = append(counts, s.Dim(fmt.Sprintf(Sym("○")+" %d no aplican", sc.NA)))
	fmt.Fprintf(w, "           %s\n", strings.Join(counts, "   "))

	// Severidad
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", s.Bold("FALLIDOS POR SEVERIDAD"))
	for _, sev := range rule.Severities {
		c, ok := sc.BySeverity[string(sev)]
		if !ok || c.Total == 0 {
			continue
		}
		label := pad(SeverityLabel(sev), 9)
		count := fmt.Sprintf("%2d de %-3d", c.Failed, c.Passed+c.Failed)
		if c.Failed > 0 {
			fmt.Fprintf(w, "  %s %s %s\n", sevColor(s, sev)(label), count, sevColor(s, sev)(strings.Repeat("■", min(c.Failed, 40))))
		} else {
			fmt.Fprintf(w, "  %s %s %s\n", s.Dim(label), count, s.Green(Sym("✓")))
		}
	}

	// Categorías
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", s.Bold("POR CATEGORÍA"))
	for _, c := range sc.ByCategory {
		if c.Passed+c.Failed == 0 {
			continue
		}
		fmt.Fprintf(w, "  %s %s %s %s\n", pad(c.Name, 24), scoreColor(s, c.Value)(fmt.Sprintf("%3d", c.Value)),
			bar(s, c.Value, 20), s.Dim(fmt.Sprintf("%d/%d", c.Passed, c.Passed+c.Failed)))
	}

	// Hallazgos
	type group struct {
		status engine.Status
		title  string
		icon   func(string) string
		mark   string
	}
	groups := []group{
		{engine.Fail, "FALLIDOS", s.Red, Sym("✗")},
		{engine.Error, "ERRORES", s.Yellow, "!"},
	}
	if o.ShowAll {
		groups = append(groups,
			group{engine.Skipped, "SIN EVALUAR · REQUIEREN PRIVILEGIOS", s.Yellow, Sym("⊘")},
			group{engine.Pass, "SUPERADOS", s.Green, Sym("✓")},
			group{engine.NA, "NO APLICAN", s.Dim, Sym("○")})
	}
	for _, g := range groups {
		var rs []engine.Result
		for _, r := range rep.Results {
			if r.Status == g.status {
				rs = append(rs, r)
			}
		}
		if len(rs) == 0 {
			continue
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s %s\n", s.Bold(g.title), s.Dim(fmt.Sprintf("(%d)", len(rs))))
		fmt.Fprintln(w, "  "+line)
		for _, r := range rs {
			sev := sevColor(s, r.Rule.Severity)(pad(SeverityLabel(r.Rule.Severity), 8))
			fmt.Fprintf(w, "  %s %s %s %s\n", g.icon(g.mark), sev, s.Cyan(pad(r.Rule.ID, 13)), r.Rule.Title)
			detail := detailLine(r.Eval)
			if detail != "" && g.status != engine.Pass && g.status != engine.Skipped {
				fmt.Fprintf(w, "  %s %s\n", strings.Repeat(" ", 24), s.Dim(detail))
			}
		}
	}
	// Sin --all, los no evaluados se resumen en una línea: el motivo es el
	// mismo para todos y ya se ha avisado arriba.
	if sc.Skipped > 0 && !o.ShowAll {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s %s %s\n", s.Yellow(Sym("⊘")), fmt.Sprintf("%s sin evaluar por falta de privilegios.", plural(sc.Skipped, "control", "controles")),
			s.Dim("Lista: bastion scan --all"))
	}
	fmt.Fprintln(w)
}

// AdminHint explica cómo repetir con privilegios en cada sistema.
func AdminHint(family string) string {
	if family == "windows" {
		return "Abre PowerShell como administrador (clic derecho → Ejecutar como administrador) y repite el comando."
	}
	return "Repite el comando con sudo."
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// detailLine resume la evidencia de una evaluación en una línea.
func detailLine(ev engine.Eval) string {
	leaf := FocusLeaf(ev)
	var parts []string
	if leaf.Label != "" {
		parts = append(parts, leaf.Label+":")
	}
	if leaf.Status == engine.NA || leaf.Status == engine.Error || leaf.Status == engine.Skipped {
		if leaf.Message != "" {
			parts = append(parts, leaf.Message)
		}
		return strings.Join(parts, " ")
	}
	if leaf.Actual != "" {
		parts = append(parts, "actual "+truncate(leaf.Actual, 48))
	}
	if leaf.Expected != "" {
		parts = append(parts, "· esperado "+truncate(leaf.Expected, 48))
	}
	return strings.Join(parts, " ")
}

// RiskLabel traduce el riesgo de rotura de una remediación.
func RiskLabel(r string) string {
	if l, ok := map[string]string{"none": "ninguno", "low": "bajo", "medium": "medio", "high": "alto"}[r]; ok {
		return l
	}
	return r
}

// FocusLeaf baja por una evaluación compuesta hasta la primera hoja con el
// mismo estado que la raíz: es la que explica el resultado.
func FocusLeaf(ev engine.Eval) engine.Eval {
	for len(ev.Children) > 0 {
		next := ev.Children[0]
		for _, c := range ev.Children {
			if c.Status == ev.Status {
				next = c
				break
			}
		}
		if next.Label == "" && len(next.Children) == 0 {
			next.Label = ev.Label
		}
		ev = next
	}
	return ev
}

func bar(s Style, v, width int) string {
	filled := v * width / 100
	return scoreColor(s, v)(strings.Repeat("█", filled)) + s.Dim(strings.Repeat("░", width-filled))
}

func scoreColor(s Style, v int) func(string) string {
	switch {
	case v >= 80:
		return s.Green
	case v >= 60:
		return s.Yellow
	}
	return s.Red
}

func sevColor(s Style, sev rule.Severity) func(string) string {
	switch sev {
	case rule.SevCritical:
		return s.BoldRed
	case rule.SevHigh:
		return s.Red
	case rule.SevMedium:
		return s.Yellow
	case rule.SevLow:
		return s.Blue
	}
	return s.Dim
}

func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%d ms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1f s", d.Seconds())
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
