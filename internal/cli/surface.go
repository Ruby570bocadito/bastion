package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/internal/report"
	"github.com/Ruby570bocadito/bastion/internal/surface"
	"github.com/Ruby570bocadito/bastion/internal/version"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

func newSurfaceCmd() *cobra.Command {
	var format, failOn string
	var outputs []string
	var all bool
	cmd := &cobra.Command{
		Use:   "surface",
		Short: "Analizar la superficie de ataque: qué servicios escuchan en la red (solo lectura)",
		Long: `Responde a "¿qué puede tocar un atacante desde la red?":

  - servicios a la escucha con su dirección, alcance (red o solo local),
    proceso y, en Windows, servicios que lo usan;
  - servicios de riesgo expuestos (Telnet, SMB, RDP, Redis, Docker API…)
    con el motivo y cómo cerrarlos;
  - recursos compartidos (SMB, NFS, Samba) abiertos a todos;
  - miembros con privilegios de administración.

Calcula una puntuación de exposición de 0 a 100. Es de SOLO LECTURA; para
corregir lo que abren las reglas del firewall, "bastion surface fix".
Ejecuta como administrador o root para ver el proceso de cada puerto.`,
		Example: `  bastion surface
  bastion surface --all                 # incluir lo que solo escucha en localhost
  bastion surface --format json > superficie.json
  bastion surface -o superficie.html    # informe autocontenido para compartir o imprimir
  bastion surface --fail-on high        # código 2 si hay hallazgos altos o críticos (CI/CD)
  bastion surface fix                   # plan para limitar a la red local lo abierto a cualquiera`,
		RunE: func(cmd *cobra.Command, _ []string) error { return runSurface(format, outputs, failOn, all) },
	}
	fl := cmd.Flags()
	fl.StringVarP(&format, "format", "f", "console", "salida estándar: console | json")
	fl.StringSliceVarP(&outputs, "output", "o", nil, "guardar el análisis en ficheros .html (informe para compartir) o .json; se puede repetir")
	fl.StringVar(&failOn, "fail-on", "", "salir con código 2 si hay hallazgos de esta severidad o mayor: critical | high | medium | low")
	fl.BoolVarP(&all, "all", "a", false, "mostrar también los servicios que solo escuchan en el propio equipo")
	cmd.AddCommand(newSurfaceFixCmd())
	return cmd
}

// analyzeSurface recoge el inventario y lo analiza.
func analyzeSurface(ctx context.Context) (*surface.Report, error) {
	inv, err := surface.Collect(ctx)
	if err != nil {
		return nil, err
	}
	return surface.Analyze(inv, platform.Detect(), version.Version, time.Now()), nil
}

func runSurface(format string, outputs []string, failOn string, all bool) error {
	if format != "console" && format != "json" {
		return fmt.Errorf("--format debe ser console o json")
	}
	var threshold rule.Severity
	if failOn != "" {
		threshold = rule.Severity(strings.ToLower(failOn))
		if !threshold.Valid() || threshold == rule.SevInfo {
			return fmt.Errorf("--fail-on debe ser critical, high, medium o low")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep, err := analyzeSurface(ctx)
	if err != nil {
		return err
	}
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		report.SurfaceConsole(os.Stdout, rep, all, stdoutStyle())
	}
	for _, output := range outputs {
		var buf bytes.Buffer
		switch strings.ToLower(filepath.Ext(output)) {
		case ".json":
			b, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				return err
			}
			buf.Write(append(b, '\n'))
		case ".html", ".htm":
			if err := report.SurfaceHTML(&buf, rep); err != nil {
				return err
			}
		default:
			return fmt.Errorf("-o admite .html o .json (%s)", output)
		}
		if err := os.WriteFile(output, buf.Bytes(), 0o640); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "  %s Análisis guardado: %s\n", report.Sym("→"), output)
	}
	if threshold != "" {
		for _, f := range rep.Findings {
			if f.Severity.Rank() <= threshold.Rank() {
				return &ExitError{Code: 2, Msg: fmt.Sprintf("hay hallazgos de severidad %s o mayor", strings.ToLower(report.SeverityLabel(threshold)))}
			}
		}
	}
	return nil
}
