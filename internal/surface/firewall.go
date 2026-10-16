package surface

import (
	"fmt"
	"strconv"
	"strings"
)

// FirewallProfile es un perfil del Firewall de Windows (Dominio, Privado o
// Público) con su estado.
type FirewallProfile struct {
	Name         string `json:"name"`
	Bit          int    `json:"-"`
	Enabled      bool   `json:"enabled"`
	BlockInbound bool   `json:"block_inbound"` // acción de entrada por defecto: bloquear
	Active       bool   `json:"active"`        // perfil de alguna red conectada ahora
}

// FirewallRule es una regla de entrada habilitada.
type FirewallRule struct {
	Name       string
	Allow      bool
	Protocol   int    // 6 TCP, 17 UDP, 256 cualquiera
	LocalPorts string // "*", "80,443", "5000-5010", "RPC", "RPC-EPMap"…
	App        string // ruta del programa (vacía = cualquiera)
	Service    string // nombre del servicio, "*" (cualquier servicio) o vacío
	Profiles   int    // máscara de perfiles
	Remote     string // direcciones remotas permitidas ("*" = cualquiera)
}

// Firewall es la política de entrada efectiva del Firewall de Windows.
type Firewall struct {
	Profiles []FirewallProfile `json:"profiles"`
	Rules    []FirewallRule    `json:"-"`
	// InboundRules es el número de reglas de entrada habilitadas.
	InboundRules int `json:"inbound_rules"`
}

var profileNames = map[int]string{1: "Dominio", 2: "Privado", 4: "Público"}

// Active devuelve los perfiles en uso (todos si no consta ninguno).
func (fw *Firewall) Active() []FirewallProfile {
	var out []FirewallProfile
	for _, p := range fw.Profiles {
		if p.Active {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return fw.Profiles
	}
	return out
}

// Evaluate decide si se puede llegar al puerto desde la red con la
// política actual, como lo hace el Firewall de Windows: en cada perfil
// activo, una regla de bloqueo gana a una de permiso; sin regla, manda la
// acción por defecto. why explica la decisión (regla o perfil).
func (fw *Firewall) Evaluate(p Port) (open bool, why string) {
	var blockedBy []string
	for _, prof := range fw.Active() {
		if !prof.Enabled {
			return true, "desactivado en el perfil " + prof.Name
		}
		if r := fw.match(p, prof.Bit, false); r != nil {
			blockedBy = append(blockedBy, fmt.Sprintf("regla de bloqueo «%s»", r.Name))
			continue
		}
		if !prof.BlockInbound {
			return true, "el perfil " + prof.Name + " permite la entrada por defecto"
		}
		if r := fw.match(p, prof.Bit, true); r != nil {
			why := fmt.Sprintf("lo permite la regla «%s» (perfil %s", r.Name, prof.Name)
			if r.Remote != "" && r.Remote != "*" {
				why += ", solo desde " + r.Remote
			}
			return true, why + ")"
		}
	}
	if len(blockedBy) > 0 {
		return false, strings.Join(blockedBy, ", ")
	}
	names := make([]string, 0, 3)
	for _, prof := range fw.Active() {
		names = append(names, prof.Name)
	}
	return false, "ninguna regla lo permite en el perfil " + strings.Join(names, ", ")
}

// match devuelve la primera regla (de permiso o de bloqueo) que se aplica
// al puerto en el perfil indicado.
func (fw *Firewall) match(p Port, profile int, allow bool) *FirewallRule {
	for i := range fw.Rules {
		r := &fw.Rules[i]
		if r.Allow != allow || r.Profiles&profile == 0 {
			continue
		}
		switch {
		case r.Protocol == 256:
		case r.Protocol == 6 && p.Proto == "tcp":
		case r.Protocol == 17 && p.Proto == "udp":
		default:
			continue
		}
		if !matchPorts(r.LocalPorts, p) || !matchApp(r.App, p.Process) || !matchService(r.Service, p.Services) {
			continue
		}
		return r
	}
	return nil
}

// matchPorts interpreta la lista de puertos locales de una regla.
func matchPorts(spec string, p Port) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return true
	}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		switch strings.ToLower(tok) {
		case "rpc": // extremos RPC dinámicos
			if p.Proto == "tcp" && p.Port >= 49152 {
				return true
			}
			continue
		case "rpc-epmap":
			if p.Port == 135 {
				return true
			}
			continue
		case "iphttps", "iphttpsin":
			if p.Port == 443 {
				return true
			}
			continue
		case "mdns":
			if p.Port == 5353 {
				return true
			}
			continue
		}
		if lo, hi, ok := strings.Cut(tok, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && p.Port >= a && p.Port <= b {
				return true
			}
			continue
		}
		if n, err := strconv.Atoi(tok); err == nil && n == p.Port {
			return true
		}
	}
	return false
}

// matchApp compara el programa de la regla con el proceso (por nombre de
// fichero: la regla trae la ruta, a menudo con %SystemRoot%).
func matchApp(app, process string) bool {
	app = strings.TrimSpace(app)
	if app == "" || app == "*" {
		return true
	}
	if i := strings.LastIndexAny(app, `\/`); i >= 0 {
		app = app[i+1:]
	}
	return process != "" && strings.EqualFold(app, process)
}

func matchService(svc string, services []string) bool {
	svc = strings.TrimSpace(svc)
	switch svc {
	case "":
		return true
	case "*":
		return len(services) > 0
	}
	for _, s := range services {
		if strings.EqualFold(s, svc) {
			return true
		}
	}
	return false
}
