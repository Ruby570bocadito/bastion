package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/engine"
	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/internal/surface"
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

func TestTableIgnoresColorCodes(t *testing.T) {
	red := func(s string) string { return "\x1b[31m" + s + "\x1b[0m" }
	var tb Table
	tb.Row(Styled("PUERTO", red), "PROCESO")
	tb.Row("22/tcp", Styled("sshd", red))
	tb.Row("27036/udp", "steam.exe")
	var b bytes.Buffer
	tb.Write(&b)
	plain := regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(b.String(), "")
	want := "PUERTO     PROCESO\n22/tcp     sshd\n27036/udp  steam.exe\n"
	if plain != want {
		t.Errorf("tabla:\n%q\nquiero:\n%q", plain, want)
	}
}

// El informe de superficie muestra nombres de procesos, reglas y recursos
// compartidos del equipo: tampoco pueden inyectar HTML.
func TestSurfaceHTMLNeutralizesHostileData(t *testing.T) {
	hostile := `</script><script>alert(1)</script><img src=x onerror=alert(2)>`
	rep := &surface.Report{Schema: surface.Schema, Score: 72, Grade: "C", Exposed: 1, Reachable: 1,
		Ports: []surface.Port{{Proto: "tcp", Port: 8080, Addresses: []string{"0.0.0.0"}, Scope: surface.ScopeNetwork, Process: hostile,
			Firewall: surface.FirewallOpen, FirewallWhy: "lo permite la regla «" + hostile + "»"}},
		Findings:  []surface.Finding{{ID: "SURF-APPS-OPEN", Severity: rule.SevLow, Title: hostile, Subject: "8080/tcp", FirewallRules: []string{hostile}}},
		Inventory: surface.Inventory{Shares: []surface.Share{{Kind: "smb", Name: hostile}}, Firewall: &surface.Firewall{Profiles: []surface.FirewallProfile{}}},
	}
	var buf bytes.Buffer
	if err := SurfaceHTML(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert") || strings.Contains(out, "<img src=x") {
		t.Fatal("el informe contiene HTML sin escapar procedente de los datos")
	}
	for _, mark := range []string{"__BASTION_DATA__", "__NONCE__", "__STYLE__"} {
		if strings.Contains(out, mark) {
			t.Fatalf("queda el marcador %s", mark)
		}
	}
	if !strings.Contains(out, "--page:") || !strings.Contains(out, ".ptable") {
		t.Error("faltan los estilos compartidos o los propios")
	}
	m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]{16,})'`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, `<script nonce="`+m[1]+`">`) {
		t.Fatal("la CSP y el script no comparten un nonce válido")
	}
	if strings.Contains(out, "innerHTML") || strings.Contains(out, "insertAdjacentHTML") {
		t.Error("el informe no debe insertar HTML")
	}
}
