package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/bastion/internal/config"
	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/internal/report"
	"github.com/Ruby570bocadito/bastion/internal/schedule"
)

func newScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Programar un análisis diario (escaneo y superficie de ataque)",
		Long: `Programa en el planificador del sistema un análisis diario: el Programador
de tareas en Windows (como SYSTEM) y un temporizador de systemd en Linux (o
cron, si no hay systemd).

Cada día guarda un escaneo y un análisis de superficie. Así "bastion ui"
muestra la tendencia de la postura y "bastion surface" avisa de lo que ha
cambiado: un programa recién instalado que abre un puerto, una regla del
firewall modificada… Cada ejecución queda anotada en schedule.log; si la
exposición ha crecido, la tarea termina con código 3.`,
		Example: `  bastion schedule enable              # cada día a las 09:00
  bastion schedule enable --at 13:30
  bastion schedule                     # estado y últimas ejecuciones
  bastion schedule disable`,
		RunE: func(cmd *cobra.Command, _ []string) error { return scheduleStatus() },
	}
	var at string
	var unsafePath bool
	enable := &cobra.Command{
		Use:   "enable",
		Short: "Crear o actualizar la tarea diaria",
		RunE:  func(cmd *cobra.Command, _ []string) error { return scheduleEnable(at, unsafePath) },
	}
	enable.Flags().StringVar(&at, "at", "09:00", "hora del análisis (HH:MM, 24 h); si el equipo está apagado, se hace al encenderlo")
	enable.Flags().BoolVar(&unsafePath, "unsafe-path", false, "programar aunque el ejecutable esté en una carpeta que otros usuarios pueden modificar (solo laboratorios)")
	disable := &cobra.Command{
		Use:   "disable",
		Short: "Quitar la tarea diaria (los informes guardados se conservan)",
		RunE:  func(cmd *cobra.Command, _ []string) error { return scheduleDisable() },
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Mostrar la tarea y las últimas ejecuciones",
		RunE:  func(cmd *cobra.Command, _ []string) error { return scheduleStatus() },
	}
	run := &cobra.Command{
		Use:   "run",
		Short: "Hacer ahora el análisis programado (es lo que ejecuta la tarea)",
		RunE:  func(cmd *cobra.Command, _ []string) error { return scheduleRun() },
	}
	cmd.AddCommand(enable, disable, status, run)
	return cmd
}

func requireAdmin(what string) error {
	if probes.Privileged() {
		return nil
	}
	return fmt.Errorf("%s requiere privilegios. %s", what, report.AdminHint(platform.Detect().Family))
}

func scheduleEnable(at string, unsafePath bool) error {
	if err := schedule.ValidAt(at); err != nil {
		return err
	}
	if err := requireAdmin("programar el análisis"); err != nil {
		return err
	}
	sched, err := schedule.New()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	// La tarea se ejecuta como SYSTEM o root: si un usuario sin privilegios
	// puede sustituir el ejecutable, obtiene esos privilegios.
	if err := schedule.SafeExecutable(exe); err != nil && !unsafePath {
		return fmt.Errorf("no se programa: %w. Instala Bastion con el instalador (Program Files o /usr/local/bin) y vuelve a intentarlo", err)
	}
	if err := ensureDataDirs(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, err := sched.Enable(ctx, exe, at)
	if err != nil {
		return fmt.Errorf("no se pudo programar el análisis: %w", err)
	}
	s := stdoutStyle()
	fmt.Printf("\n  %s Análisis diario programado a las %s\n", s.Green(report.Sym("✓")), s.Bold(firstNonEmpty(st.At, at)))
	printScheduleStatus(s, st)
	fmt.Printf("    %s\n\n", s.Dim("Para probarlo ahora: bastion schedule run · los resultados se ven en bastion ui"))
	return nil
}

func scheduleDisable() error {
	if err := requireAdmin("quitar el análisis programado"); err != nil {
		return err
	}
	sched, err := schedule.New()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := sched.Disable(ctx); err != nil {
		return fmt.Errorf("no se pudo quitar la tarea: %w", err)
	}
	s := stdoutStyle()
	fmt.Printf("\n  %s Análisis diario quitado. Los informes guardados se conservan.\n\n", s.Green(report.Sym("✓")))
	return nil
}

func printScheduleStatus(s report.Style, st schedule.Status) {
	if st.Mechanism != "" {
		fmt.Printf("    %s %s\n", s.Dim(pad12("Mediante")), st.Mechanism)
	}
	if st.Command != "" {
		fmt.Printf("    %s %s\n", s.Dim(pad12("Ejecuta")), st.Command)
	}
	if st.NextRun != "" {
		fmt.Printf("    %s %s\n", s.Dim(pad12("Próxima")), st.NextRun)
	}
	if st.Detail != "" {
		fmt.Printf("    %s %s\n", s.Dim(pad12("Estado")), st.Detail)
	}
}

func pad12(s string) string { return fmt.Sprintf("%-10s", s) }

func scheduleStatus() error {
	s := stdoutStyle()
	sched, err := schedule.New()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, err := sched.Get(ctx)
	fmt.Println()
	switch {
	case err != nil:
		fmt.Printf("  %s No se pudo consultar la tarea: %v\n", s.Yellow("!"), err)
	case st.Mechanism == "":
		fmt.Printf("  %s No hay análisis programado. Para programarlo: %s\n", s.Dim("·"), s.Bold("bastion schedule enable"))
	case st.Enabled:
		fmt.Printf("  %s Análisis diario a las %s\n", s.Green(report.Sym("✓")), s.Bold(st.At))
		printScheduleStatus(s, st)
	default:
		fmt.Printf("  %s Tarea programada pero desactivada\n", s.Yellow("!"))
		printScheduleStatus(s, st)
	}
	runs, err := schedule.ReadRuns(schedule.LogPath(config.DataDir()))
	switch {
	case err != nil && errors.Is(err, os.ErrPermission):
		fmt.Printf("  %s %s\n", s.Dim("·"), s.Dim("Sin privilegios no se puede leer el registro de ejecuciones."))
	case len(runs) > 0:
		fmt.Printf("\n  %s\n", s.Bold("ÚLTIMAS EJECUCIONES"))
		tb := report.Table{Indent: "  "}
		tb.Row(report.Styled("FECHA", s.Bold), report.Styled("POSTURA", s.Bold), report.Styled("EXPOSICIÓN", s.Bold), report.Styled("CAMBIOS", s.Bold))
		for i := len(runs) - 1; i >= 0 && i >= len(runs)-7; i-- {
			r := runs[i]
			changes := report.Styled("sin aumento de exposición", s.Dim)
			if r.NewExposure > 0 {
				changes = report.Styled(fmt.Sprintf("%d que aumentan la exposición", r.NewExposure), s.Red)
			}
			if len(r.Errors) > 0 {
				changes = report.Styled("error: "+strings.Join(r.Errors, "; "), s.Red)
			}
			tb.Row(r.Time.Local().Format("2006-01-02 15:04"), fmt.Sprintf("%d/100", r.ScanScore), fmt.Sprintf("%d/100", r.SurfaceScore), changes)
		}
		tb.Write(os.Stdout)
	}
	fmt.Println()
	return nil
}

// scheduleRun hace el análisis programado: guarda un escaneo y un análisis
// de superficie (comparado con el anterior) y lo anota en schedule.log.
func scheduleRun() error {
	if err := requireAdmin("el análisis programado"); err != nil {
		return err
	}
	if err := ensureDataDirs(); err != nil {
		return err
	}
	cfg := loadConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	run := schedule.Run{Time: time.Now().UTC()}

	if rep, err := scanReport(ctx, cfg, "", nil, nil, nil); err != nil {
		run.Errors = append(run.Errors, "escaneo: "+err.Error())
	} else if _, _, _, _, err := saveReport(cfg, rep); err != nil {
		run.Errors = append(run.Errors, err.Error())
	} else {
		run.ScanScore = rep.Score.Value
	}
	if srep, err := analyzeSurface(ctx); err != nil {
		run.Errors = append(run.Errors, "superficie: "+err.Error())
	} else {
		dir, userDir := attachSurfaceChanges(cfg, srep)
		if _, _, err := report.SaveSurface(dir, srep, cfg.Reports.Keep); err != nil {
			run.Errors = append(run.Errors, "superficie: "+err.Error())
		} else {
			if !userDir {
				_ = config.GrantUserRead(dir)
			}
			run.SurfaceScore = srep.Score
			if srep.Changes != nil {
				for _, c := range srep.Changes.Items {
					if c.Bad() {
						run.NewExposure++
					}
				}
			}
		}
	}
	logErr := schedule.AppendRun(schedule.LogPath(config.DataDir()), run)
	fmt.Printf("postura %d/100 · exposición %d/100 · %d cambios que aumentan la exposición\n", run.ScanScore, run.SurfaceScore, run.NewExposure)
	switch {
	case len(run.Errors) > 0:
		return &ExitError{Code: 1, Msg: strings.Join(run.Errors, "; ")}
	case run.NewExposure > 0:
		return &ExitError{Code: 3, Msg: "la exposición ha crecido desde el análisis anterior (bastion surface lo detalla)"}
	}
	if logErr != nil {
		return fmt.Errorf("no se pudo anotar la ejecución: %w", logErr)
	}
	return nil
}
