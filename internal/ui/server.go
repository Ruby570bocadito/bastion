// Package ui sirve la consola local de Bastion ("bastion ui"): un panel en
// el navegador con la postura, la tendencia, el plan de hardening, el
// historial y las excepciones del equipo.
//
// Seguridad (ver docs/adr/0008-consola-local.md):
//   - Solo escucha en la interfaz de loopback (127.0.0.1).
//   - Toda la API exige un token aleatorio de 256 bits que solo conoce
//     quien lanzó "bastion ui" (va en la URL que se abre y se envía en la
//     cabecera X-Bastion-Token). Otro usuario del mismo equipo puede
//     conectarse al puerto, pero no hacer nada sin el token.
//   - Se rechaza cualquier cabecera Host que no sea de loopback, lo que
//     frena los ataques de DNS rebinding, y no se responde a CORS: una web
//     maliciosa no puede enviar la cabecera del token ni leer respuestas.
//   - CSP estricta con nonce, como el informe HTML: los datos del sistema
//     auditado se insertan siempre con textContent.
//   - La consola solo lee y escanea. Aplicar cambios exige la terminal,
//     donde están la confirmación, la instantánea y el dead-man switch.
package ui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/engine"
	"github.com/Ruby570bocadito/bastion/internal/report"
)

//go:embed assets/ui.html
var shell []byte

// State describe el equipo y la sesión de la consola.
type State struct {
	Version    string `json:"version"`
	Hostname   string `json:"hostname"`
	System     string `json:"system"`
	Family     string `json:"family"`
	Role       string `json:"role"`
	Profile    string `json:"profile"`
	ProfileID  string `json:"profile_id"`
	IsAdmin    bool   `json:"is_admin"`
	ReportsDir string `json:"reports_dir"`
}

// PlanItem es un control fallido y lo que "harden" haría con él.
type PlanItem struct {
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Category string   `json:"category"`
	Status   string   `json:"status"`
	Reason   string   `json:"reason,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Risk     string   `json:"risk"`
	Reboot   bool     `json:"reboot,omitempty"`
	Steps    []string `json:"steps,omitempty"`
}

// Change resume un cambio de hardening aplicado.
type Change struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Wave       int       `json:"wave"`
	Status     string    `json:"status"`
	Profile    string    `json:"profile"`
	Verified   int       `json:"verified"`
	Failed     int       `json:"failed"`
	RolledBack int       `json:"rolled_back"`
	Reboot     bool      `json:"reboot,omitempty"`
}

// Exception es una excepción con su vigencia calculada.
type Exception struct {
	Rule     string   `json:"rule"`
	Reason   string   `json:"reason"`
	Owner    string   `json:"owner,omitempty"`
	Hosts    []string `json:"hosts,omitempty"`
	Created  string   `json:"created"`
	Expires  string   `json:"expires"`
	Expired  bool     `json:"expired"`
	DaysLeft int      `json:"days_left"`
}

// Backend es lo que la consola necesita de Bastion. Lo implementa la CLI.
type Backend interface {
	State() State
	// Scan evalúa el perfil, guarda el informe y lo devuelve con su ID.
	Scan(ctx context.Context) (*engine.Report, string, error)
	Reports() ([]report.Meta, error)
	Report(id string) (*engine.Report, error)
	Plan(ctx context.Context, wave int) ([]PlanItem, error)
	Changes() ([]Change, error)
	Exceptions() ([]Exception, error)
}

// Server es la consola local.
type Server struct {
	backend Backend
	token   string
	// Un único escaneo o plan a la vez: ambos leen todo el sistema.
	busy sync.Mutex
}

// New crea la consola con un token aleatorio.
func New(b Backend) (*Server, error) {
	t := make([]byte, 32)
	if _, err := rand.Read(t); err != nil {
		return nil, err
	}
	return &Server{backend: b, token: base64.RawURLEncoding.EncodeToString(t)}, nil
}

// Token es el secreto de la sesión (va en la URL que se abre).
func (s *Server) Token() string { return s.token }

// Listen abre el puerto en loopback (0 = uno libre al azar).
func Listen(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

// Serve atiende hasta que ctx se cancela.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute, // un escaneo completo en Windows tarda segundos
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Handler devuelve el enrutador con todas las protecciones aplicadas.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleShell)
	mux.Handle("GET /api/state", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		return s.backend.State(), nil
	}))
	mux.Handle("GET /api/reports", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		list, err := s.backend.Reports()
		if list == nil {
			list = []report.Meta{}
		}
		return list, err
	}))
	mux.Handle("GET /api/reports/{id}", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		id := r.PathValue("id")
		if !report.ValidReportID(id) {
			return nil, httpError{http.StatusBadRequest, "identificador de informe inválido"}
		}
		return s.backend.Report(id)
	}))
	mux.Handle("POST /api/scan", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		if !s.busy.TryLock() {
			return nil, httpError{http.StatusConflict, "ya hay un escaneo en curso"}
		}
		defer s.busy.Unlock()
		rep, id, err := s.backend.Scan(r.Context())
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": id, "report": rep}, nil
	}))
	mux.Handle("GET /api/plan", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		wave, err := strconv.Atoi(r.URL.Query().Get("wave"))
		if err != nil || wave < 1 || wave > 3 {
			return nil, httpError{http.StatusBadRequest, "wave debe ser 1, 2 o 3"}
		}
		if !s.busy.TryLock() {
			return nil, httpError{http.StatusConflict, "hay un escaneo en curso"}
		}
		defer s.busy.Unlock()
		items, err := s.backend.Plan(r.Context(), wave)
		if items == nil {
			items = []PlanItem{}
		}
		return items, err
	}))
	mux.Handle("GET /api/changes", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		list, err := s.backend.Changes()
		if list == nil {
			list = []Change{}
		}
		return list, err
	}))
	mux.Handle("GET /api/exceptions", s.api(func(w http.ResponseWriter, r *http.Request) (any, error) {
		list, err := s.backend.Exceptions()
		if list == nil {
			list = []Exception{}
		}
		return list, err
	}))
	// El informe HTML completo de un escaneo (para la pestaña Controles).
	mux.HandleFunc("GET /r/{file}", s.handleReportHTML)
	return s.guard(mux)
}

// guard aplica a todas las respuestas las cabeceras de seguridad y rechaza
// los Host que no son de loopback (DNS rebinding).
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if !loopbackHost(r.Host) {
			http.Error(w, "host no permitido", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && !loopbackOrigin(o) {
				http.Error(w, "origen no permitido", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func loopbackHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func loopbackOrigin(o string) bool {
	rest, ok := strings.CutPrefix(o, "http://")
	return ok && loopbackHost(rest)
}

func (s *Server) validToken(t string) bool {
	return t != "" && subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1
}

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }

// api envuelve un manejador JSON: exige el token y serializa la respuesta.
func (s *Server) api(fn func(http.ResponseWriter, *http.Request) (any, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if !s.validToken(r.Header.Get("X-Bastion-Token")) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token ausente o incorrecto: abre la URL que muestra \"bastion ui\""})
			return
		}
		v, err := fn(w, r)
		if err != nil {
			code := http.StatusInternalServerError
			var he httpError
			if errors.As(err, &he) {
				code = he.code
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// handleShell sirve la aplicación. No contiene datos: los pide a la API con
// el token, así que puede servirse sin él.
func (s *Server) handleShell(w http.ResponseWriter, r *http.Request) {
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "error interno", http.StatusInternalServerError)
		return
	}
	n := base64.RawURLEncoding.EncodeToString(nonce)
	w.Header().Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; script-src 'nonce-%s'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", n))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(bytes.ReplaceAll(shell, []byte("__NONCE__"), []byte(n)))
}

// handleReportHTML sirve el informe HTML de un escaneo guardado. Va en un
// iframe de la propia consola, así que el token llega en la URL (?t=).
func (s *Server) handleReportHTML(w http.ResponseWriter, r *http.Request) {
	if !s.validToken(r.URL.Query().Get("t")) {
		http.Error(w, "token ausente o incorrecto", http.StatusUnauthorized)
		return
	}
	id, ok := strings.CutSuffix(r.PathValue("file"), ".html")
	if !ok || !report.ValidReportID(id) {
		http.NotFound(w, r)
		return
	}
	rep, err := s.backend.Report(id)
	if err != nil {
		http.Error(w, "informe no disponible", http.StatusNotFound)
		return
	}
	// El informe trae su propia CSP con nonce; aquí solo se limita quién
	// puede incrustarlo.
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	if err := report.HTML(&buf, rep); err != nil {
		http.Error(w, "error interno", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}
