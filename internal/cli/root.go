// Package cli implementa la línea de comandos de Bastion.
package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/bastion/internal/config"
	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/internal/remediate"
	"github.com/Ruby570bocadito/bastion/internal/report"
	"github.com/Ruby570bocadito/bastion/internal/version"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
	"github.com/Ruby570bocadito/bastion/rules"
)

// ExitError permite devolver un código de salida concreto.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

type globalFlags struct {
	noColor  bool
	rulesDir []string
}

var gf globalFlags

// Execute ejecuta la CLI y devuelve el código de salida.
func Execute() int {
	root := newRoot()
	if err := root.Execute(); err != nil {
		if ee, ok := err.(*ExitError); ok {
			if ee.Msg != "" {
				fmt.Fprintln(os.Stderr, ee.Msg)
			}
			return ee.Code
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "bastion",
		Short: "Bastion · auditoría y hardening para Windows, Windows Server y Linux",
		Long: `Bastion evalúa la configuración de seguridad del equipo frente a perfiles de
hardening (CIS, STIG, baselines de Microsoft), calcula una puntuación de postura
y genera informes con evidencias y pasos de remediación.

Bastion solo LEE la configuración del sistema: "scan" nunca modifica nada.

Primeros pasos:
  bastion info                      qué plataforma y perfil se han detectado
  bastion scan                      auditar con el perfil por defecto
  bastion scan --save --open        guardar el informe HTML y abrirlo
  bastion rules show LNX-SSH-001    detalle de un control`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
	}
	root.SetVersionTemplate(version.String() + "\n")
	root.PersistentFlags().BoolVar(&gf.noColor, "no-color", false, "desactivar colores")
	root.PersistentFlags().StringSliceVar(&gf.rulesDir, "rules-dir", nil, "directorios adicionales de reglas (*.yaml)")
	root.AddCommand(newScanCmd(), newHardenCmd(), newRollbackCmd(), newHistoryCmd(), newDeadmanCmd(), newInfoCmd(), newRulesCmd(), newProfilesCmd(), newUpdateCmd(), newInitCmd(), newVersionCmd())
	root.CompletionOptions.HiddenDefaultCmd = true
	return root
}

// loadConfig lee config.yaml y avisa de los problemas reales. Sin
// privilegios el fichero no se puede leer (en Windows la carpeta es solo
// para administradores): se usan los valores por defecto sin avisar.
func loadConfig() config.Config {
	cfg, err := config.Load()
	if err != nil && !(errors.Is(err, fs.ErrPermission) && !probes.Privileged()) {
		fmt.Fprintln(os.Stderr, "aviso:", err)
	}
	return cfg
}

// reportsDir es donde "scan --save" guarda los informes: el directorio de
// la configuración o, sin privilegios, la carpeta del usuario (en Windows
// solo los administradores pueden escribir en %ProgramData%\Bastion).
func reportsDir(cfg config.Config) (dir string, user bool) {
	if probes.Privileged() || os.Getenv("BASTION_HOME") != "" {
		return cfg.Reports.Dir, false
	}
	if d, err := config.UserReportsDir(); err == nil {
		return d, true
	}
	return cfg.Reports.Dir, false
}

// loadCatalog carga el paquete oficial y las reglas adicionales.
func loadCatalog(cfg config.Config) (*rule.Catalog, error) {
	c := rule.NewCatalog()
	if err := c.LoadFS(rules.FS, "rules/"); err != nil {
		return nil, fmt.Errorf("paquete oficial de reglas: %w", err)
	}
	dirs := append([]string{}, cfg.Rules.ExtraDirs...)
	dirs = append(dirs, gf.rulesDir...)
	for _, d := range dirs {
		if err := c.LoadDir(d); err != nil {
			return nil, fmt.Errorf("reglas de %s: %w", d, err)
		}
	}
	if errs := c.Validate(probes.KnownSet(), remediate.ValidateAction); len(errs) > 0 {
		var b strings.Builder
		for _, e := range errs {
			b.WriteString("\n  · " + e.Error())
		}
		return nil, fmt.Errorf("hay reglas inválidas:%s", b.String())
	}
	return c, nil
}

// resolveProfile elige el perfil pedido o el de por defecto de la plataforma.
func resolveProfile(c *rule.Catalog, info platform.Info, requested string) (*rule.Profile, error) {
	if requested != "" && requested != "auto" {
		p := c.Profiles[requested]
		if p == nil {
			var ids []string
			for _, x := range c.ProfilesFor(info.Tags) {
				ids = append(ids, x.ID)
			}
			return nil, fmt.Errorf("perfil %q desconocido; disponibles para este equipo: %s", requested, strings.Join(ids, ", "))
		}
		return p, nil
	}
	p := c.DefaultProfile(info.Tags)
	if p == nil {
		return nil, fmt.Errorf("no hay un perfil por defecto para %s (%s); usa --profile", info.Name, strings.Join(info.Tags, ", "))
	}
	return p, nil
}

func stdoutStyle() report.Style { return report.NewStyle(os.Stdout, gf.noColor) }
func stderrStyle() report.Style { return report.NewStyle(os.Stderr, gf.noColor) }
