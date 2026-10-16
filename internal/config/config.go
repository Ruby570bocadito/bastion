// Package config gestiona las rutas de Bastion y el fichero config.yaml.
//
// Rutas por defecto:
//
//	Linux:   /etc/bastion (configuración)  ·  /var/lib/bastion (datos)
//	Windows: %ProgramData%\Bastion (ambos)
//
// BASTION_HOME sustituye ambas rutas (útil para desarrollo y pruebas).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config es el contenido de config.yaml.
type Config struct {
	// Profile es el perfil por defecto: "auto" lo elige según la plataforma.
	Profile string `yaml:"profile"`
	Reports struct {
		Dir  string `yaml:"dir"`
		Keep int    `yaml:"keep"`
	} `yaml:"reports"`
	Rules struct {
		ExtraDirs []string `yaml:"extra_dirs"`
	} `yaml:"rules"`
	Update struct {
		Repo        string `yaml:"repo"`
		ReleasesURL string `yaml:"releases_url"`
	} `yaml:"update"`
	Notify Notify `yaml:"notify"`
}

// Notify configura los avisos del análisis programado.
type Notify struct {
	// Webhook recibe el aviso (ntfy, Slack, Discord, Teams o JSON). Su
	// dirección suele llevar un secreto: el fichero solo lo leen los
	// administradores.
	Webhook string `yaml:"webhook,omitempty"`
	// Format fuerza el formato; vacío, se deduce de la dirección.
	Format string `yaml:"format,omitempty"`
	// When es "changes" (por defecto: solo si algo empeora o falla) o
	// "always" (también las ejecuciones sin cambios a peor).
	When string `yaml:"when,omitempty"`
}

// ConfigDir es el directorio de configuración.
func ConfigDir() string {
	if h := os.Getenv("BASTION_HOME"); h != "" {
		return h
	}
	if runtime.GOOS == "windows" {
		return programData()
	}
	return "/etc/bastion"
}

// DataDir es el directorio de datos (informes, instantáneas).
func DataDir() string {
	if h := os.Getenv("BASTION_HOME"); h != "" {
		return h
	}
	if runtime.GOOS == "windows" {
		return programData()
	}
	return "/var/lib/bastion"
}

func programData() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Bastion")
}

// UserReportsDir es el directorio de informes del usuario actual. Se usa
// cuando Bastion se ejecuta sin privilegios y no puede escribir en DataDir:
//
//	Windows: %LOCALAPPDATA%\Bastion\reports
//	Linux:   $XDG_DATA_HOME/bastion/reports (~/.local/share/bastion/reports)
func UserReportsDir() (string, error) {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "Bastion", "reports"), nil
		}
		return "", errors.New("LOCALAPPDATA no está definido")
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "bastion", "reports"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "bastion", "reports"), nil
}

// File es la ruta de config.yaml.
func File() string { return filepath.Join(ConfigDir(), "config.yaml") }

// Default devuelve la configuración por defecto.
func Default() Config {
	var c Config
	c.Profile = "auto"
	c.Reports.Dir = filepath.Join(DataDir(), "reports")
	c.Reports.Keep = 30
	c.Rules.ExtraDirs = []string{filepath.Join(ConfigDir(), "rules.d")}
	return c
}

// Load lee config.yaml; si no existe devuelve la configuración por defecto.
func Load() (Config, error) {
	c := Default()
	b, err := os.ReadFile(File())
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Default(), fmt.Errorf("%s: %w", File(), err)
	}
	if c.Reports.Dir == "" {
		c.Reports.Dir = Default().Reports.Dir
	}
	if c.Profile == "" {
		c.Profile = "auto"
	}
	return c, nil
}

const defaultFile = `# Configuración de Bastion · https://github.com/Ruby570bocadito/bastion
# Este fichero solo debe poder modificarlo un administrador.

# Perfil por defecto para "bastion scan". "auto" lo elige según la plataforma
# (win-workstation-l1, win-server-l1, win-dc-l1, linux-server-l1...).
profile: auto

reports:
  # Dónde se guardan los informes HTML y JSON de "bastion scan --save".
  dir: %q
  # Número de escaneos que se conservan (los más antiguos se borran).
  keep: 30

rules:
  # Directorios con reglas propias (*.yaml) que se suman al paquete oficial.
  extra_dirs:
    - %q

update:
  # Repositorio de GitHub del que se descargan las actualizaciones.
  # repo: Ruby570bocadito/bastion
  # Espejo interno de releases (redes corporativas o aisladas).
  # Debe servir <url>/latest/download/version.txt y <url>/download/<tag>/<fichero>.
  # releases_url: https://mirror.interno/bastion/releases

# Avisos del análisis programado ("bastion schedule"). Cada ejecución queda en
# el Visor de eventos (Windows) o en syslog (Linux); además, un webhook
# opcional. Se configura con: bastion schedule notify --set <url>
# notify:
#   webhook: https://ntfy.sh/<tema-secreto>
#   format: ntfy      # ntfy, slack, discord, teams o json (se deduce de la url)
#   when: changes     # changes (solo si algo empeora o falla) o always
`

// InitResult resume lo que hizo Init.
type InitResult struct {
	Created []string
	Config  string
}

// Init crea los directorios y un config.yaml por defecto si no existe.
// No sobrescribe nunca una configuración existente.
func Init() (InitResult, error) {
	var res InitResult
	d := Default()
	dirs := []string{ConfigDir(), DataDir(), d.Reports.Dir, d.Rules.ExtraDirs[0], filepath.Join(DataDir(), "snapshots")}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return res, err
			}
			res.Created = append(res.Created, dir)
		}
	}
	res.Config = File()
	if _, err := os.Stat(res.Config); errors.Is(err, fs.ErrNotExist) {
		content := fmt.Sprintf(defaultFile, d.Reports.Dir, d.Rules.ExtraDirs[0])
		if err := os.WriteFile(res.Config, []byte(content), 0o640); err != nil {
			return res, err
		}
		res.Created = append(res.Created, res.Config)
	}
	if err := restrictPermissions(DataDir()); err != nil {
		return res, err
	}
	if ConfigDir() != DataDir() {
		if err := restrictPermissions(ConfigDir()); err != nil {
			return res, err
		}
	}
	if err := GrantUserRead(d.Reports.Dir); err != nil {
		return res, err
	}
	return res, nil
}

// SetNotify guarda la configuración de avisos en config.yaml. Solo cambia
// la sección notify (la quita y la añade al final): el resto del fichero y
// sus comentarios quedan igual. Con webhook vacío la quita.
func SetNotify(n Notify) error {
	path := File()
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		d := Default()
		b = []byte(fmt.Sprintf(defaultFile, d.Reports.Dir, d.Rules.ExtraDirs[0]))
	} else if err != nil {
		return err
	}
	var cur Config
	if err := yaml.Unmarshal(b, &cur); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var out []string
	in := false
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "notify:"):
			in = true
			continue
		case in && (l == "" || l[0] == ' ' || l[0] == '\t'):
			continue
		}
		in = false
		out = append(out, l)
	}
	text := strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"
	if n.Webhook != "" {
		text += "\nnotify:\n"
		for _, kv := range [][2]string{{"webhook", n.Webhook}, {"format", n.Format}, {"when", n.When}} {
			if kv[1] != "" {
				// Una cadena JSON es una cadena YAML válida entre comillas.
				q, _ := json.Marshal(kv[1])
				text += "  " + kv[0] + ": " + string(q) + "\n"
			}
		}
	}
	var check Config
	if err := yaml.Unmarshal([]byte(text), &check); err != nil || check.Notify != n {
		return fmt.Errorf("no se pudo actualizar %s sin estropearlo: edítalo a mano", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
