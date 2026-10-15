package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/engine"
	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// Un valor leído del sistema auditado (p. ej. una línea de sudoers) no debe
// poder romper la etiqueta <script> ni inyectar HTML en el informe.
func TestHTMLNeutralizesHostileData(t *testing.T) {
	hostile := `</script><script>alert(1)</script><img src=x onerror=alert(2)>`
	rep := &engine.Report{
		Schema: engine.SchemaVersion,
		Results: []engine.Result{{
			Rule: &rule.Rule{ID: "T-X-001", Title: hostile, Severity: rule.SevHigh, Category: "x"},
			Eval: engine.Eval{Status: engine.Fail, Actual: hostile},
		}},
	}
	var buf bytes.Buffer
	if err := HTML(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert") || strings.Contains(out, "<img src=x") {
		t.Fatal("el informe contiene HTML sin escapar procedente de los datos")
	}
	if strings.Contains(out, "__BASTION_DATA__") || strings.Contains(out, "__NONCE__") {
		t.Fatal("quedan marcadores sin sustituir")
	}
	m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]{16,})'`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, `<script nonce="`+m[1]+`">`) {
		t.Fatal("la CSP y el script no comparten un nonce válido")
	}
	var buf2 bytes.Buffer
	_ = HTML(&buf2, rep)
	if m2 := regexp.MustCompile(`'nonce-([^']+)'`).FindStringSubmatch(buf2.String()); m2 == nil || m2[1] == m[1] {
		t.Fatal("el nonce debe ser aleatorio en cada informe")
	}
}

func TestFocusLeaf(t *testing.T) {
	ev := engine.Eval{Status: engine.Fail, Children: []engine.Eval{
		{Status: engine.Pass, Label: "a"},
		{Status: engine.Fail, Children: []engine.Eval{{Status: engine.Fail, Label: "b", Actual: "1"}}},
	}}
	if l := FocusLeaf(ev); l.Label != "b" || l.Actual != "1" {
		t.Errorf("FocusLeaf = %+v", l)
	}
}

func TestSavedReports(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	for i, v := range []int{40, 65, 88} {
		rep := &engine.Report{Schema: engine.SchemaVersion, FinishedAt: base.Add(time.Duration(i) * time.Hour),
			Host: platform.Info{Hostname: "pc-01"}, Score: engine.Score{Value: v, Grade: "X"}}
		if _, _, err := Save(dir, rep, 30); err != nil {
			t.Fatal(err)
		}
	}
	other := &engine.Report{FinishedAt: base, Host: platform.Info{Hostname: "otro"}}
	if _, _, err := Save(dir, other, 30); err != nil {
		t.Fatal(err)
	}
	list, err := ListSaved(dir, "PC-01")
	if err != nil || len(list) != 3 {
		t.Fatalf("ListSaved: %v %d", err, len(list))
	}
	if list[0].Score.Value != 40 || list[2].Score.Value != 88 {
		t.Errorf("orden cronológico: %d → %d", list[0].Score.Value, list[2].Score.Value)
	}
	rep, err := LoadSaved(dir, list[2].ID)
	if err != nil || rep.Score.Value != 88 {
		t.Errorf("LoadSaved: %v %+v", err, rep)
	}
	for _, bad := range []string{"../etc/passwd", "bastion-x-20261015-100000/../../a", "x.json", ""} {
		if _, err := LoadSaved(dir, bad); err == nil {
			t.Errorf("%q debería rechazarse", bad)
		}
	}
}
