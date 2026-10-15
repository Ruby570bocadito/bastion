package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/bastion/internal/config"
	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/internal/report"
	"github.com/Ruby570bocadito/bastion/internal/selfupdate"
	"github.com/Ruby570bocadito/bastion/internal/version"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// ---- info ------------------------------------------------------------------

func newInfoCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Mostrar la plataforma detectada, el perfil por defecto y las rutas",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _ := config.Load()
			info := platform.Detect()
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			prof, _ := resolveProfile(cat, info, cfg.Profile)
			if asJSON {
				out := map[string]any{"version": version.Version, "host": info, "config": config.File(), "reports": cfg.Reports.Dir}
				if prof != nil {
					out["default_profile"] = prof.ID
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			s := stdoutStyle()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			row := func(k, v string) { fmt.Fprintf(w, "  %s\t%s\n", s.Dim(k), v) }
			fmt.Fprintln(os.Stdout)
			row("Versión", version.String())
			row("Equipo", info.Hostname)
			row("Sistema", info.DisplayName())
			if info.Build != "" {
				row("Build", info.Build)
			}
			if info.Kernel != "" {
				row("Kernel", info.Kernel)
			}
			row("Arquitectura", info.Arch)
			row("Rol", info.Role)
			if info.DomainJoined {
				row("Dominio", info.Domain)
			}
			row("Etiquetas", strings.Join(info.Tags, ", "))
			row("Administrador", map[bool]string{true: s.Green("sí"), false: s.Yellow("no (algunos controles no se podrán leer)")}[info.IsAdmin])
			if prof != nil {
				row("Perfil por defecto", prof.ID+" · "+prof.Name)
			}
			row("Reglas aplicables", fmt.Sprint(len(cat.Select(info.Tags, profID(prof)))))
			row("Probes disponibles", strings.Join(probes.Available(), ", "))
			row("Configuración", config.File())
			row("Informes", cfg.Reports.Dir)
			w.Flush()
			fmt.Fprintln(os.Stdout)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "salida JSON")
	return cmd
}

func profID(p *rule.Profile) string {
	if p == nil {
		return ""
	}
	return p.ID
}

// ---- rules -----------------------------------------------------------------

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "Consultar y validar reglas"}

	var all bool
	var profile string
	list := &cobra.Command{
		Use:   "list",
		Short: "Listar las reglas aplicables a este equipo (o todas con --all)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _ := config.Load()
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			var rs []*rule.Rule
			switch {
			case all:
				rs = append(rs, cat.Rules...)
				rule.SortRules(rs)
			default:
				info := platform.Detect()
				p, err := resolveProfile(cat, info, firstNonEmpty(profile, cfg.Profile))
				if err != nil {
					return err
				}
				rs = cat.Select(info.Tags, p.ID)
			}
			s := stdoutStyle()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Bold("ID"), s.Bold("SEVERIDAD"), s.Bold("CATEGORÍA"), s.Bold("TÍTULO"))
			for _, r := range rs {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.ID, report.SeverityLabel(r.Severity), r.Category, r.Title)
			}
			w.Flush()
			fmt.Printf("\n%d reglas\n", len(rs))
			return nil
		},
	}
	list.Flags().BoolVar(&all, "all", false, "todas las plataformas y perfiles")
	list.Flags().StringVarP(&profile, "profile", "p", "", "perfil")

	show := &cobra.Command{
		Use:   "show <ID>",
		Short: "Mostrar el detalle y la remediación de una regla",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := config.Load()
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			r := cat.Rule(args[0])
			if r == nil {
				return fmt.Errorf("no existe la regla %s", args[0])
			}
			printRule(r)
			return nil
		},
	}

	lint := &cobra.Command{
		Use:   "lint [directorio...]",
		Short: "Validar el paquete oficial y, opcionalmente, reglas propias",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.Default()
			cfg.Rules.ExtraDirs = args
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			fmt.Printf(report.Sym("✓")+" %d reglas y %d perfiles válidos\n", len(cat.Rules), len(cat.Profiles))
			return nil
		},
	}
	doc := &cobra.Command{
		Use:   "doc",
		Short: "Generar el catálogo de controles en Markdown (docs/06-catalogo-de-controles.md)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _ := config.Load()
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			writeCatalogMarkdown(os.Stdout, cat)
			return nil
		},
	}
	cmd.AddCommand(list, show, lint, doc)
	return cmd
}

// writeCatalogMarkdown genera el catálogo de controles implementados.
func writeCatalogMarkdown(w io.Writer, cat *rule.Catalog) {
	groups := []struct {
		title string
		match func(*rule.Rule) bool
	}{
		{"Linux", func(r *rule.Rule) bool { return strings.HasPrefix(r.Platforms[0], "linux") }},
		{"Windows y Windows Server", func(r *rule.Rule) bool { return strings.HasPrefix(r.Platforms[0], "windows") }},
	}
	profiles := make([]*rule.Profile, 0, len(cat.Profiles))
	for _, p := range cat.Profiles {
		profiles = append(profiles, p)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })

	fmt.Fprintln(w, "<!-- Generado con \"bastion rules doc\". No editar a mano: edita las reglas en rules/. -->")
	auto := 0
	for _, r := range cat.Rules {
		if len(r.Remediation.Actions) > 0 {
			auto++
		}
	}
	fmt.Fprintf(w, "\n**%d controles** en el paquete oficial, **%d con corrección automática** (`bastion harden`). ⚡ = afecta al acceso remoto (requiere `--include-remote`).\n\n", len(cat.Rules), auto)
	fmt.Fprintln(w, "### Perfiles")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Perfil | Nombre | Hereda de | Por defecto en |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, p := range profiles {
		fmt.Fprintf(w, "| `%s` | %s | %s | %s |\n", p.ID, p.Name, strings.Join(p.Extends, ", "), strings.Join(p.DefaultFor, ", "))
	}
	for _, g := range groups {
		var rs []*rule.Rule
		for _, r := range cat.Rules {
			if g.match(r) {
				rs = append(rs, r)
			}
		}
		sort.SliceStable(rs, func(i, j int) bool {
			if rs[i].Category != rs[j].Category {
				return rs[i].Category < rs[j].Category
			}
			return rs[i].ID < rs[j].ID
		})
		fmt.Fprintf(w, "\n### %s (%d)\n", g.title, len(rs))
		cur := ""
		for _, r := range rs {
			if r.Category != cur {
				cur = r.Category
				fmt.Fprintf(w, "\n#### %s\n\n", cur)
				fmt.Fprintln(w, "| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |")
				fmt.Fprintln(w, "|---|---|---|---|---|---|---|")
			}
			auto := ""
			if len(r.Remediation.Actions) > 0 {
				auto = "✓"
				if r.Remediation.Safety == "remote-access" {
					auto = "✓ ⚡"
				}
			}
			fmt.Fprintf(w, "| `%s` | %s | %s | %s | %s | %s | %s |\n", r.ID, strings.ReplaceAll(r.Title, "|", "\\|"),
				strings.ToLower(report.SeverityLabel(r.Severity)), strings.Join(r.Profiles, ", "),
				strings.Join(r.References.MitreTechniques, ", "), report.RiskLabel(r.Remediation.BreakingRisk), auto)
		}
	}
}

func printRule(r *rule.Rule) {
	s := stdoutStyle()
	sec := func(t string) { fmt.Printf("\n  %s\n", s.Bold(strings.ToUpper(t))) }
	para := func(t string) {
		for _, l := range strings.Split(strings.TrimSpace(t), "\n") {
			fmt.Printf("  %s\n", l)
		}
	}
	fmt.Printf("\n  %s  %s\n", s.Cyan(s.Bold(r.ID)), s.Bold(r.Title))
	fmt.Printf("  %s · %s · %s\n", report.SeverityLabel(r.Severity), r.Category, s.Dim(strings.Join(r.Platforms, ", ")))
	sec("Descripción")
	para(r.Description)
	if r.Rationale != "" {
		sec("Por qué importa")
		para(r.Rationale)
	}
	sec("Remediación")
	para(r.Remediation.Summary)
	if r.Remediation.GPO != "" {
		fmt.Printf("  %s %s\n", s.Dim("GPO:"), r.Remediation.GPO)
	}
	if r.Remediation.Commands != "" {
		fmt.Println()
		for _, l := range strings.Split(strings.TrimRight(r.Remediation.Commands, "\n"), "\n") {
			fmt.Printf("    %s\n", s.Green(l))
		}
	}
	if n := len(r.Remediation.Actions); n > 0 {
		cmdline := "bastion harden --rule " + r.ID + " --apply"
		if w := rule.RiskWave(r.Remediation.BreakingRisk); w > 1 {
			cmdline += fmt.Sprintf(" --wave %d", w)
		}
		if r.Remediation.Safety == "remote-access" {
			cmdline += " --include-remote"
		}
		fmt.Printf("\n  %s %d acción(es) automática(s) · %s\n", s.Green("Corrección automática:"), n, s.Bold(cmdline))
	}
	fmt.Printf("\n  %s %s", s.Dim("Riesgo de rotura:"), report.RiskLabel(r.Remediation.BreakingRisk))
	if r.Remediation.RebootRequired {
		fmt.Print(" · requiere reinicio")
	}
	fmt.Println()
	if r.Impact != "" {
		sec("Impacto")
		para(r.Impact)
	}
	refs := r.References
	var parts []string
	add := func(label string, xs []string) {
		if len(xs) > 0 {
			parts = append(parts, label+" "+strings.Join(xs, ", "))
		}
	}
	add("ATT&CK", refs.MitreTechniques)
	add("Mitigaciones", refs.MitreMitigations)
	add("NIST 800-53", refs.NIST)
	add("CIS", refs.CIS)
	add("STIG", refs.STIG)
	add("ENS", refs.ENS)
	if len(parts) > 0 {
		sec("Referencias")
		for _, p := range parts {
			fmt.Printf("  %s\n", p)
		}
	}
	fmt.Printf("\n  %s %s · perfiles: %s\n\n", s.Dim("Fuente:"), r.Source, strings.Join(r.Profiles, ", "))
}

// ---- profiles ----------------------------------------------------------------

func newProfilesCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "Listar los perfiles de hardening disponibles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _ := config.Load()
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			info := platform.Detect()
			tags := info.Tags
			if all {
				tags = nil
			}
			def := cat.DefaultProfile(info.Tags)
			s := stdoutStyle()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Bold("PERFIL"), s.Bold("NOMBRE"), s.Bold("HEREDA DE"), s.Bold("REGLAS"))
			for _, p := range cat.ProfilesFor(tags) {
				mark := ""
				if def != nil && p.ID == def.ID {
					mark = s.Green(" (por defecto)")
				}
				n := len(cat.Select(representativeTags(p.Platforms), p.ID))
				if !all {
					n = len(cat.Select(info.Tags, p.ID))
				}
				fmt.Fprintf(w, "%s%s\t%s\t%s\t%d\n", p.ID, mark, p.Name, strings.Join(p.Extends, ", "), n)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "incluir perfiles de otras plataformas")
	return cmd
}

// ---- update ------------------------------------------------------------------

func newUpdateCmd() *cobra.Command {
	var check, force bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Actualizar Bastion (y su paquete de reglas) a la última versión",
		Long: `Descarga la última release, verifica su suma SHA-256 y sustituye el binario.
Las reglas oficiales van incrustadas en el binario, así que también se actualizan.

Origen: https://github.com/<repo>/releases (configurable en config.yaml o con
BASTION_REPO / BASTION_RELEASES_URL para usar un espejo interno).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _ := config.Load()
			src := selfupdate.Source{
				Repo:    firstNonEmpty(os.Getenv("BASTION_REPO"), cfg.Update.Repo, version.Repo),
				BaseURL: firstNonEmpty(os.Getenv("BASTION_RELEASES_URL"), cfg.Update.ReleasesURL),
			}
			s := stdoutStyle()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			fmt.Printf("  Comprobando %s …\n", src.Base())
			latest, err := src.Latest(ctx)
			if err != nil {
				return fmt.Errorf("no se pudo consultar la última versión: %w", err)
			}
			current := version.Version
			newer := selfupdate.Newer(latest, current)
			fmt.Printf("  Versión instalada: %s · última publicada: %s\n", current, latest)
			if !newer && !force {
				fmt.Printf("  %s Bastion está actualizado.\n", s.Green(report.Sym("✓")))
				return nil
			}
			if check {
				fmt.Printf("  %s Hay una versión nueva. Ejecuta: bastion update\n", s.Yellow(report.Sym("↑")))
				return nil
			}
			fmt.Printf("  Descargando %s …\n", selfupdate.AssetName(runtimeGOOS(), runtimeGOARCH()))
			bin, tmp, err := src.Download(ctx, latest)
			if err != nil {
				return err
			}
			defer os.RemoveAll(tmp)
			fmt.Printf("  %s Suma SHA-256 verificada\n", s.Green(report.Sym("✓")))
			if err := selfupdate.Apply(bin); err != nil {
				return err
			}
			fmt.Printf("  %s Actualizado a %s\n", s.Green(report.Sym("✓")), latest)
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "solo comprobar si hay una versión nueva")
	cmd.Flags().BoolVar(&force, "force", false, "reinstalar aunque no haya versión nueva")
	return cmd
}

// ---- init ----------------------------------------------------------------------

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Preparar directorios y configuración (lo ejecuta el instalador)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			selfupdate.CleanupOld()
			res, err := config.Init()
			if err != nil {
				return fmt.Errorf("init: %w (¿se ejecuta como administrador/root?)", err)
			}
			s := stdoutStyle()
			sort.Strings(res.Created)
			for _, c := range res.Created {
				fmt.Printf("  %s creado %s\n", s.Green("+"), c)
			}
			fmt.Printf("  %s Bastion preparado · configuración: %s\n", s.Green(report.Sym("✓")), res.Config)
			return nil
		},
	}
}

// ---- version --------------------------------------------------------------------

func newVersionCmd() *cobra.Command {
	var short bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Mostrar la versión",
		Run: func(cmd *cobra.Command, _ []string) {
			if short {
				fmt.Println(version.Version)
				return
			}
			fmt.Println(version.String())
		},
	}
	cmd.Flags().BoolVar(&short, "short", false, "solo el número de versión")
	return cmd
}

// representativeTags expande las plataformas de un perfil a las etiquetas
// que tendría un equipo típico de esa plataforma (para contar reglas).
func representativeTags(platforms []string) []string {
	expand := map[string][]string{
		"windows-dc":     {"windows-dc", "windows-server", "windows"},
		"windows-server": {"windows-member", "windows-server", "windows"},
		"windows-member": {"windows-member", "windows-server", "windows"},
		"windows-client": {"windows-client", "windows"},
		"linux":          {"linux-ubuntu", "linux-debian", "linux"},
	}
	var out []string
	for _, p := range platforms {
		if e, ok := expand[p]; ok {
			out = append(out, e...)
		} else {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
