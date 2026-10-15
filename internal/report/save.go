package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/engine"
)

// JSON escribe el informe en el formato estable bastion.report/v1.
func JSON(w io.Writer, rep *engine.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// WriteFile genera el informe en path según su extensión (.html o .json).
func WriteFile(path string, rep *engine.Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	switch strings.ToLower(filepath.Ext(path)) {
	case ".html", ".htm":
		return HTML(f, rep)
	case ".json":
		return JSON(f, rep)
	}
	return fmt.Errorf("formato no soportado para %s (usa .html o .json)", path)
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Save guarda el informe HTML y JSON en dir con un nombre con fecha y
// conserva solo los keep escaneos más recientes. Devuelve (html, json).
func Save(dir string, rep *engine.Report, keep int) (string, string, error) {
	host := unsafeName.ReplaceAllString(rep.Host.Hostname, "_")
	base := fmt.Sprintf("bastion-%s-%s", host, rep.FinishedAt.Local().Format("20060102-150405"))
	htmlPath := filepath.Join(dir, base+".html")
	jsonPath := filepath.Join(dir, base+".json")
	if err := WriteFile(htmlPath, rep); err != nil {
		return "", "", err
	}
	if err := WriteFile(jsonPath, rep); err != nil {
		return "", "", err
	}
	if keep > 0 {
		prune(dir, keep)
	}
	return htmlPath, jsonPath, nil
}

// prune borra los informes más antiguos dejando keep escaneos.
func prune(dir string, keep int) {
	for _, ext := range []string{".html", ".json"} {
		files, _ := filepath.Glob(filepath.Join(dir, "bastion-*"+ext))
		sort.Strings(files) // el nombre incluye la fecha
		if len(files) > keep {
			for _, f := range files[:len(files)-keep] {
				os.Remove(f)
			}
		}
	}
}

// Open abre un fichero con la aplicación por defecto (navegador para HTML).
func Open(path string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "rundll32.exe"), "url.dll,FileProtocolHandler", path).Start()
	case "darwin":
		return exec.Command("open", path).Start()
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return fmt.Errorf("no hay entorno gráfico")
	}
	return exec.Command("xdg-open", path).Start()
}

// Meta resume un informe guardado: lo justo para listar el historial y
// dibujar la tendencia sin cargar los resultados.
type Meta struct {
	ID          string       `json:"id"`
	FinishedAt  time.Time    `json:"finished_at"`
	Hostname    string       `json:"hostname"`
	Profile     string       `json:"profile"`
	ProfileName string       `json:"profile_name"`
	Version     string       `json:"version"`
	Score       engine.Score `json:"score"`
}

var reReportID = regexp.MustCompile(`^bastion-[A-Za-z0-9._-]+-[0-9]{8}-[0-9]{6}$`)

// ValidReportID indica si id es el nombre (sin extensión) de un informe
// guardado. Impide rutas fuera del directorio de informes.
func ValidReportID(id string) bool { return reReportID.MatchString(id) && !strings.Contains(id, "..") }

// ListSaved devuelve los informes JSON guardados en dir, del más antiguo
// al más reciente. Si host no está vacío, solo los de ese equipo.
func ListSaved(dir, host string) ([]Meta, error) {
	files, err := filepath.Glob(filepath.Join(dir, "bastion-*.json"))
	if err != nil {
		return nil, err
	}
	var out []Meta
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		if !ValidReportID(id) {
			continue
		}
		var partial struct {
			FinishedAt time.Time `json:"finished_at"`
			Tool       struct {
				Version string `json:"version"`
			} `json:"tool"`
			Host struct {
				Hostname string `json:"hostname"`
			} `json:"host"`
			Profile struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"profile"`
			Score engine.Score `json:"score"`
		}
		b, err := os.ReadFile(f)
		if err != nil || json.Unmarshal(b, &partial) != nil {
			continue
		}
		if host != "" && !strings.EqualFold(partial.Host.Hostname, host) {
			continue
		}
		partial.Score.BySeverity, partial.Score.ByCategory = nil, nil
		out = append(out, Meta{ID: id, FinishedAt: partial.FinishedAt, Hostname: partial.Host.Hostname,
			Profile: partial.Profile.ID, ProfileName: partial.Profile.Name, Version: partial.Tool.Version, Score: partial.Score})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FinishedAt.Before(out[j].FinishedAt) })
	return out, nil
}

// LoadSaved carga un informe JSON guardado por su ID.
func LoadSaved(dir, id string) (*engine.Report, error) {
	if !ValidReportID(id) {
		return nil, fmt.Errorf("identificador de informe inválido")
	}
	b, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		return nil, err
	}
	var rep engine.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	return &rep, nil
}
