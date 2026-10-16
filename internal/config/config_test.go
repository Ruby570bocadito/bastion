package config

import (
	"os"
	"strings"
	"testing"
)

func TestSetNotify(t *testing.T) {
	t.Setenv("BASTION_HOME", t.TempDir())
	// Sin config.yaml: se crea el de por defecto con la sección.
	if err := SetNotify(Notify{Webhook: "https://ntfy.sh/bastion-rby", When: "always"}); err != nil {
		t.Fatal(err)
	}
	c, err := Load()
	if err != nil || c.Notify.Webhook != "https://ntfy.sh/bastion-rby" || c.Notify.When != "always" || c.Notify.Format != "" || c.Reports.Keep != 30 {
		t.Fatalf("tras crear: %+v %v", c, err)
	}
	b, _ := os.ReadFile(File())
	if !strings.Contains(string(b), "# Perfil por defecto") || !strings.Contains(string(b), "# releases_url:") {
		t.Errorf("se conservan los comentarios:\n%s", b)
	}

	// Cambiarla no la duplica y respeta el resto.
	if err := os.WriteFile(File(), []byte(strings.Replace(string(b), "keep: 30", "keep: 12", 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := SetNotify(Notify{Webhook: "https://hooks.slack.com/services/T/B/X", Format: "slack"}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(File())
	c, _ = Load()
	if strings.Count(string(b), "\nnotify:") != 1 || c.Notify.Format != "slack" || c.Notify.When != "" || c.Reports.Keep != 12 {
		t.Errorf("tras cambiar: %+v\n%s", c.Notify, b)
	}

	// Sin webhook se quita la sección.
	if err := SetNotify(Notify{}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(File())
	if c, _ := Load(); c.Notify.Webhook != "" || strings.Contains(string(b), "\nnotify:") {
		t.Errorf("tras quitar:\n%s", b)
	}

	// Un config.yaml roto no se sobrescribe.
	if err := os.WriteFile(File(), []byte("profile: [roto"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := SetNotify(Notify{Webhook: "https://ntfy.sh/x"}); err == nil {
		t.Error("con un config.yaml roto debería fallar")
	}
}
