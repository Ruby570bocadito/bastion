package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/engine"
	"github.com/Ruby570bocadito/bastion/internal/report"
	"github.com/Ruby570bocadito/bastion/internal/surface"
)

const goodID = "bastion-pc-01-20261015-100000"

type fakeBackend struct {
	scans   int
	block   chan struct{}
	started chan struct{}
}

func (f *fakeBackend) State() State { return State{Hostname: "pc-01", Version: "test"} }
func (f *fakeBackend) Scan(ctx context.Context) (*engine.Report, string, error) {
	f.scans++
	if f.block != nil {
		close(f.started)
		<-f.block
	}
	return &engine.Report{Score: engine.Score{Value: 77}}, goodID, nil
}
func (f *fakeBackend) Reports() ([]report.Meta, error) {
	return []report.Meta{{ID: goodID, FinishedAt: time.Now()}}, nil
}
func (f *fakeBackend) Report(id string) (*engine.Report, error) {
	if id != goodID {
		return nil, errors.New("no existe")
	}
	return &engine.Report{Schema: engine.SchemaVersion, Score: engine.Score{Value: 77}}, nil
}
func (f *fakeBackend) Plan(ctx context.Context, wave int) ([]PlanItem, error) {
	return []PlanItem{{RuleID: "WIN-NET-006", Status: "planned"}}, nil
}
func (f *fakeBackend) Changes() ([]Change, error)       { return nil, nil }
func (f *fakeBackend) Exceptions() ([]Exception, error) { return nil, nil }
func (f *fakeBackend) Surface(ctx context.Context) (*surface.Report, error) {
	return &surface.Report{Schema: surface.Schema, Score: 85}, nil
}

func newTest(t *testing.T) (*Server, http.Handler, *fakeBackend) {
	t.Helper()
	fb := &fakeBackend{}
	s, err := New(fb)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Token()) < 40 {
		t.Fatalf("token demasiado corto: %q", s.Token())
	}
	return s, s.Handler(), fb
}

func do(h http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "127.0.0.1:8790"
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestShellCSP(t *testing.T) {
	_, h, _ := newTest(t)
	rec := do(h, "GET", "/", nil)
	if rec.Code != 200 {
		t.Fatalf("GET / = %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]+)'`).FindStringSubmatch(csp)
	if m == nil || !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP inesperada: %s", csp)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<script nonce="`+m[1]+`">`) || strings.Contains(body, "__NONCE__") {
		t.Error("el script debe llevar el nonce de la cabecera")
	}
	if strings.Contains(body, "innerHTML") || strings.Contains(body, "insertAdjacentHTML") {
		t.Error("la consola no debe insertar HTML")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("faltan cabeceras de seguridad")
	}
}

func TestToken(t *testing.T) {
	s, h, _ := newTest(t)
	for name, hdr := range map[string]map[string]string{
		"sin token":     nil,
		"token erróneo": {"X-Bastion-Token": "x" + s.Token()[1:]},
		"en la query":   nil, // la API no acepta el token en la URL
	} {
		target := "/api/state"
		if name == "en la query" {
			target += "?t=" + s.Token()
		}
		if rec := do(h, "GET", target, hdr); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, quiero 401", name, rec.Code)
		}
	}
	rec := do(h, "GET", "/api/state", map[string]string{"X-Bastion-Token": s.Token()})
	var st State
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.Hostname != "pc-01" {
		t.Errorf("con token: %d %s", rec.Code, rec.Body)
	}
}

func TestHostAndOrigin(t *testing.T) {
	s, h, fb := newTest(t)
	tok := map[string]string{"X-Bastion-Token": s.Token()}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{"X-Bastion-Token": s.Token()}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	// DNS rebinding: un dominio del atacante que resuelve a 127.0.0.1.
	for _, host := range []string{"evil.example:8790", "127.0.0.1.evil.example", "192.168.1.10:8790"} {
		if rec := do(h, "GET", "/", map[string]string{"Host": host}); rec.Code != http.StatusForbidden {
			t.Errorf("Host %s: %d, quiero 403", host, rec.Code)
		}
	}
	for _, host := range []string{"localhost:9000", "[::1]:8790", "127.0.0.1"} {
		if rec := do(h, "GET", "/api/state", with(map[string]string{"Host": host})); rec.Code != 200 {
			t.Errorf("Host %s: %d, quiero 200", host, rec.Code)
		}
	}
	if rec := do(h, "POST", "/api/scan", with(map[string]string{"Origin": "https://evil.example"})); rec.Code != http.StatusForbidden || fb.scans != 0 {
		t.Errorf("POST desde otro origen: %d (escaneos %d)", rec.Code, fb.scans)
	}
	if rec := do(h, "POST", "/api/scan", with(map[string]string{"Origin": "http://127.0.0.1:8790"})); rec.Code != 200 || fb.scans != 1 {
		t.Errorf("POST desde la consola: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "GET", "/api/scan", tok); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/scan: %d, quiero 405", rec.Code)
	}
}

func TestReportIDs(t *testing.T) {
	s, h, _ := newTest(t)
	tok := map[string]string{"X-Bastion-Token": s.Token()}
	if rec := do(h, "GET", "/api/reports/"+goodID, tok); rec.Code != 200 {
		t.Errorf("informe válido: %d", rec.Code)
	}
	for _, id := range []string{"..%2F..%2Fetc%2Fpasswd", "bastion-x", "%2E%2E"} {
		if rec := do(h, "GET", "/api/reports/"+id, tok); rec.Code == 200 {
			t.Errorf("%s debería rechazarse", id)
		}
	}
	if rec := do(h, "GET", "/r/"+goodID+".html", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("informe HTML sin token: %d", rec.Code)
	}
	rec := do(h, "GET", "/r/"+goodID+".html?t="+s.Token(), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "bastion-data") {
		t.Errorf("informe HTML: %d", rec.Code)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp != "frame-ancestors 'self'" {
		t.Errorf("el informe solo debe poder incrustarse en la consola: %q", csp)
	}
	if rec := do(h, "GET", "/r/../x.html?t="+s.Token(), nil); rec.Code == 200 {
		t.Error("ruta fuera del directorio aceptada")
	}
}

func TestPlanAndBusy(t *testing.T) {
	s, h, fb := newTest(t)
	tok := map[string]string{"X-Bastion-Token": s.Token()}
	for _, w := range []string{"0", "4", "x", ""} {
		if rec := do(h, "GET", "/api/plan?wave="+w, tok); rec.Code != http.StatusBadRequest {
			t.Errorf("wave=%q: %d, quiero 400", w, rec.Code)
		}
	}
	if rec := do(h, "GET", "/api/plan?wave=2", tok); rec.Code != 200 || !strings.Contains(rec.Body.String(), "WIN-NET-006") {
		t.Errorf("plan: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "GET", "/api/surface", tok); rec.Code != 200 || !strings.Contains(rec.Body.String(), surface.Schema) {
		t.Errorf("superficie: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "GET", "/api/surface", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("superficie sin token: %d", rec.Code)
	}

	// Mientras un escaneo está en curso, otro escaneo responde 409 y el plan
	// espera a que termine (no falla).
	fb.block, fb.started = make(chan struct{}), make(chan struct{})
	done := make(chan int)
	go func() { done <- do(h, "POST", "/api/scan", tok).Code }()
	<-fb.started
	if rec := do(h, "POST", "/api/scan", tok); rec.Code != http.StatusConflict {
		t.Errorf("segundo escaneo: %d, quiero 409", rec.Code)
	}
	planDone := make(chan int)
	go func() { planDone <- do(h, "GET", "/api/plan?wave=1", tok).Code }()
	select {
	case code := <-planDone:
		t.Fatalf("el plan no debe adelantarse al escaneo en curso (respondió %d)", code)
	case <-time.After(100 * time.Millisecond):
	}
	close(fb.block)
	if code := <-done; code != 200 {
		t.Errorf("primer escaneo: %d", code)
	}
	if code := <-planDone; code != 200 {
		t.Errorf("plan tras el escaneo: %d", code)
	}
}

func TestListenLoopback(t *testing.T) {
	l, err := Listen(0)
	if err != nil {
		t.Skip("sin red de loopback:", err)
	}
	defer l.Close()
	if !strings.HasPrefix(l.Addr().String(), "127.0.0.1:") {
		t.Errorf("escucha en %s, quiero solo 127.0.0.1", l.Addr())
	}
}
