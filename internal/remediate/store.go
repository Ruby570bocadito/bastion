package remediate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// ManifestSchema es la versión del formato de manifiesto de cambios.
const ManifestSchema = "bastion.change/v1"

// Estados de un cambio.
const (
	StatusInProgress = "in-progress"
	StatusApplied    = "applied"
	StatusPartial    = "partial"
	StatusFailed     = "failed"
	StatusRolledBack = "rolled-back"
	StatusNothing    = "nothing"
)

// Entry es una acción aplicada (o intentada) con su estado previo.
type Entry struct {
	Seq          int         `json:"seq"`
	RuleID       string      `json:"rule_id"`
	Action       rule.Action `json:"action"`
	Description  string      `json:"description"`
	Before       State       `json:"before"`
	RemoteAccess bool        `json:"remote_access,omitempty"`
	// Attempted se marca ANTES de aplicar (registro previo): si el proceso
	// muere a mitad, el rollback también restaura esta entrada.
	Attempted  bool   `json:"attempted"`
	Applied    bool   `json:"applied"`
	RolledBack bool   `json:"rolled_back,omitempty"`
	Error      string `json:"error,omitempty"`
}

// RuleOutcome es el resultado final de una regla dentro de un cambio.
type RuleOutcome struct {
	RuleID  string `json:"rule_id"`
	Title   string `json:"title"`
	Outcome string `json:"outcome"`
	Message string `json:"message,omitempty"`
}

// Manifest describe un cambio completo y permite deshacerlo.
type Manifest struct {
	Schema          string        `json:"schema"`
	ID              string        `json:"id"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
	ToolVersion     string        `json:"tool_version"`
	Host            string        `json:"host"`
	Profile         string        `json:"profile"`
	Wave            int           `json:"wave"`
	Status          string        `json:"status"`
	RebootRequired  bool          `json:"reboot_required,omitempty"`
	Confirmed       bool          `json:"confirmed,omitempty"`
	DeadmanDeadline *time.Time    `json:"deadman_deadline,omitempty"`
	DeadmanFired    bool          `json:"deadman_fired,omitempty"`
	Entries         []*Entry      `json:"entries"`
	Rules           []RuleOutcome `json:"rules"`

	store *Store
	mu    sync.Mutex
}

var reChangeID = regexp.MustCompile(`^chg-[0-9]{8}-[0-9]{6}(-[0-9]+)?$`)

// Store guarda los manifiestos en <datos>/snapshots/<id>/manifest.json.
type Store struct{ Dir string }

// NewManifest crea un manifiesto vacío con un ID basado en la fecha.
func (s *Store) NewManifest(host, profile, version string, wave int) *Manifest {
	now := time.Now()
	id := "chg-" + now.Format("20060102-150405")
	for i := 2; ; i++ {
		if _, err := os.Stat(filepath.Join(s.Dir, id)); errors.Is(err, fs.ErrNotExist) {
			break
		}
		id = fmt.Sprintf("chg-%s-%d", now.Format("20060102-150405"), i)
	}
	return &Manifest{Schema: ManifestSchema, ID: id, CreatedAt: now.UTC(), ToolVersion: version,
		Host: host, Profile: profile, Wave: wave, Status: StatusInProgress, store: s}
}

// Save escribe el manifiesto de forma atómica.
func (m *Manifest) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.UpdatedAt = time.Now().UTC()
	dir := filepath.Join(m.store.Dir, m.ID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "manifest.json.tmp")
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "manifest.json"))
}

// Load lee un manifiesto por ID.
func (s *Store) Load(id string) (*Manifest, error) {
	if !reChangeID.MatchString(id) {
		return nil, fmt.Errorf("ID de cambio inválido: %q (formato chg-AAAAMMDD-HHMMSS)", id)
	}
	b, err := os.ReadFile(filepath.Join(s.Dir, id, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("no existe el cambio %s", id)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	m.store = s
	return &m, nil
}

// List devuelve los manifiestos, del más reciente al más antiguo.
func (s *Store) List() ([]*Manifest, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Manifest
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "chg-") {
			continue
		}
		if m, err := s.Load(e.Name()); err == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Latest devuelve el último cambio que se puede deshacer.
func (s *Store) Latest() (*Manifest, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	for _, m := range all {
		if m.Status != StatusRolledBack && m.Status != StatusNothing && m.pending(nil) > 0 {
			return m, nil
		}
	}
	return nil, errors.New("no hay cambios que deshacer")
}

func (m *Manifest) pending(filter func(*Entry) bool) int {
	n := 0
	for _, e := range m.Entries {
		if e.Attempted && !e.RolledBack && (filter == nil || filter(e)) {
			n++
		}
	}
	return n
}

// Lock evita dos operaciones de hardening simultáneas. Un bloqueo de más
// de 30 minutos se considera abandonado.
func (s *Store) Lock() (func(), error) {
	if err := os.MkdirAll(s.Dir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(s.Dir, ".lock")
	if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) > 30*time.Minute {
		os.Remove(path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("hay otra operación de hardening en curso (si no es así, borra %s)", path)
	}
	fmt.Fprintf(f, "%d %s\n", os.Getpid(), time.Now().Format(time.RFC3339))
	f.Close()
	return func() { os.Remove(path) }, nil
}

// Log añade una línea al registro de cambios (changes.log, JSON por línea).
func (s *Store) Log(id, ruleID, event, detail string) {
	f, err := os.OpenFile(filepath.Join(s.Dir, "changes.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(map[string]string{
		"time": time.Now().UTC().Format(time.RFC3339), "change": id, "rule": ruleID, "event": event, "detail": detail,
	})
	f.Write(append(b, '\n'))
}
