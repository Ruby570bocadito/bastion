package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/Ruby570bocadito/bastion/internal/surface"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// SurfaceConsole escribe el análisis de superficie de ataque para humanos.
// Sin all, los servicios que solo escuchan en el propio equipo se resumen.
func SurfaceConsole(w io.Writer, rep *surface.Report, all bool, s Style) {
	line := s.Dim(strings.Repeat("─", 72))
	host := rep.Host
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s  %s %s\n", s.Bold(s.Cyan(Sym("▲")+" BASTION")), s.Dim("·"), s.Dim("superficie de ataque  "+rep.Version))
	fmt.Fprintln(w, "  "+line)
	fmt.Fprintf(w, "  %s %s %s\n", s.Dim(pad("Equipo", 9)), s.Bold(host.Hostname), s.Dim("· "+host.DisplayName()))
	loopback := len(rep.Listeners) - rep.Exposed
	fmt.Fprintf(w, "  %s %d a la escucha · %s · %d solo locales\n", s.Dim(pad("Puertos", 9)), len(rep.Listeners),
		s.Bold(fmt.Sprintf("%d en la red", rep.Exposed)), loopback)

	fmt.Fprintln(w)
	c := scoreColor(s, rep.Score)
	fmt.Fprintf(w, "  %s  %s %s  %s\n", s.Bold("EXPOSICIÓN"), c(s.Bold(fmt.Sprintf("%3d/100", rep.Score))), c(s.Bold(rep.Grade)), bar(s, rep.Score, 32))
	counts := map[rule.Severity]int{}
	for _, f := range rep.Findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, sev := range rule.Severities {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(SeverityLabel(sev))))
		}
	}
	summary := s.Green(Sym("✓") + " sin hallazgos")
	if len(rep.Findings) > 0 {
		summary = s.Red(Sym("✗")+" "+plural(len(rep.Findings), "hallazgo", "hallazgos")) + s.Dim(" ("+strings.Join(parts, ", ")+")")
	}
	fmt.Fprintf(w, "              %s\n", summary)

	if len(rep.Findings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s %s\n", s.Bold("HALLAZGOS"), s.Dim(fmt.Sprintf("(%d)", len(rep.Findings))))
		fmt.Fprintln(w, "  "+line)
		for _, f := range rep.Findings {
			sev := f.Severity
			fmt.Fprintf(w, "  %s %s %s %s\n", s.Red(Sym("✗")), sevColor(s, sev)(pad(SeverityLabel(sev), 8)), s.Cyan(pad(f.Subject, 10)), f.Title)
			fmt.Fprintf(w, "  %s %s\n", strings.Repeat(" ", 21), s.Dim(f.Detail))
			fmt.Fprintf(w, "  %s %s\n", strings.Repeat(" ", 21), s.Green(Sym("→")+" "+f.Fix))
		}
	}

	fmt.Fprintln(w)
	shown := 0
	for _, l := range rep.Listeners {
		if all || l.Scope == surface.ScopeNetwork {
			shown++
		}
	}
	title := "PUERTOS EXPUESTOS EN LA RED"
	if all {
		title = "PUERTOS A LA ESCUCHA"
	}
	fmt.Fprintf(w, "  %s %s\n", s.Bold(title), s.Dim(fmt.Sprintf("(%d)", shown)))
	fmt.Fprintln(w, "  "+line)
	if shown == 0 {
		fmt.Fprintf(w, "  %s\n", s.Green(Sym("✓")+" Ningún servicio escucha en la red."))
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", s.Dim("PUERTO"), s.Dim("DIRECCIÓN"), s.Dim("ALCANCE"), s.Dim("PROCESO"), s.Dim("SERVICIO"))
		for _, l := range rep.Listeners {
			if !all && l.Scope != surface.ScopeNetwork {
				continue
			}
			proc := l.Process
			if l.PID > 0 {
				proc = strings.TrimSpace(proc + " (" + strconv.Itoa(l.PID) + ")")
			}
			if len(l.Services) > 0 {
				proc += " · " + strings.Join(l.Services, ", ")
			}
			if proc == "" {
				proc = s.Dim("?")
			}
			scope := s.Yellow("red")
			if l.Scope == surface.ScopeLoopback {
				scope = s.Dim("local")
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", fmt.Sprintf("%d/%s", l.Port, l.Proto), l.Address, scope, truncate(proc, 44), l.Known)
		}
		tw.Flush()
	}
	if !all && loopback > 0 {
		fmt.Fprintf(w, "  %s\n", s.Dim(fmt.Sprintf("+ %d solo accesibles desde este equipo (bastion surface --all)", loopback)))
	}

	if len(rep.Shares) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s %s\n", s.Bold("RECURSOS COMPARTIDOS"), s.Dim(fmt.Sprintf("(%d)", len(rep.Shares))))
		fmt.Fprintln(w, "  "+line)
		for _, sh := range rep.Shares {
			var acc []string
			for _, a := range sh.Access {
				x := a.Account + ": " + a.Right
				if a.Deny {
					x += " (denegado)"
				}
				acc = append(acc, x)
			}
			acc = append(acc, sh.Options...)
			name := sh.Name
			if sh.Path != "" && sh.Path != sh.Name {
				name += " " + s.Dim(sh.Path)
			}
			fmt.Fprintf(w, "  %s %s  %s\n", s.Dim(pad(sh.Kind, 6)), name, s.Dim(strings.Join(acc, " · ")))
		}
	}
	if len(rep.Admins) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s %s\n", s.Bold("ADMINISTRADORES"), s.Dim(fmt.Sprintf("(%d)", len(rep.Admins))))
		fmt.Fprintln(w, "  "+line)
		for _, a := range rep.Admins {
			extra := strings.Trim(strings.Join([]string{a.Kind, a.Source}, " · "), " ·")
			fmt.Fprintf(w, "  %s %s\n", a.Name, s.Dim(extra))
		}
	}

	fmt.Fprintln(w)
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "  %s %s\n", s.Yellow("!"), s.Dim(n))
	}
	fmt.Fprintf(w, "  %s %s\n\n", s.Dim("·"), s.Dim("Bastion todavía no evalúa las reglas del firewall: un puerto en la red puede estar filtrado. Compruébalo antes de darlo por accesible."))
}
