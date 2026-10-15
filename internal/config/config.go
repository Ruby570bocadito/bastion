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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

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
