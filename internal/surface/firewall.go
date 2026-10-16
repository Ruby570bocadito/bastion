package surface

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Estados de un puerto frente al firewall.
const (
	FirewallOpen     = "open"     // se puede llegar desde cualquier dirección
	FirewallLimited  = "limited"  // solo desde ciertas redes, direcciones o interfaces
	FirewallFiltered = "filtered" // lo bloquea el firewall
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
	Local      string // direcciones locales (destino) a las que se aplica ("*" = todas)
	Remote     string // direcciones remotas permitidas ("*" = cualquiera)
	Interfaces string // interfaces concretas (vacío = todas)
	IfTypes    string // tipos de interfaz: All, Lan, Wireless, RemoteAccess
}

// Firewall es la política de entrada efectiva del Firewall de Windows.
type Firewall struct {
	Profiles []FirewallProfile `json:"profiles"`
	Rules    []FirewallRule    `json:"-"`
	// InboundRules es el número de reglas de entrada habilitadas.
	InboundRules int `json:"inbound_rules"`
}

// Access es el resultado de evaluar un puerto.
type Access struct {
	State string // FirewallOpen | FirewallLimited | FirewallFiltered
	// Limit resume desde dónde se llega cuando está limitado ("Tailscale",
	// "red local", "desde 10.0.0.0/8"…).
	Limit string
	// Why explica la decisión (reglas y perfil) para poder comprobarla.
	Why string
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

// Evaluate decide desde dónde se puede llegar al puerto con la política
// actual, como lo hace el Firewall de Windows: en cada perfil activo, una
// regla de bloqueo gana a una de permiso y, sin regla, manda la acción por
// defecto. Una regla de permiso puede estar limitada a ciertas direcciones
// locales (p. ej. «Tailscale-In», solo hacia la IP de Tailscale), remotas
// (LocalSubnet) o interfaces: entonces el puerto queda "limitado".
func (fw *Firewall) Evaluate(p Port) Access {
	var limits, limitRules, blocked []string
	for _, prof := range fw.Active() {
		if !prof.Enabled {
			return Access{State: FirewallOpen, Why: "firewall desactivado en el perfil " + prof.Name}
		}
		if r := fw.fullBlock(p, prof.Bit); r != nil {
			blocked = append(blocked, fmt.Sprintf("regla de bloqueo «%s»", r.Name))
			continue
		}
		if !prof.BlockInbound {
			return Access{State: FirewallOpen, Why: "el perfil " + prof.Name + " permite la entrada por defecto"}
		}
		for i := range fw.Rules {
			r := &fw.Rules[i]
			if !r.Allow || !r.matches(p, prof.Bit) {
				continue
			}
			limit, applies := r.limit(p)
			if !applies {
				continue
			}
			if limit == "" {
				return Access{State: FirewallOpen, Why: fmt.Sprintf("lo permite la regla «%s» (perfil %s)", r.Name, prof.Name)}
			}
			limits = appendOnce(limits, limit)
			limitRules = appendOnce(limitRules, fmt.Sprintf("«%s»", r.Name))
		}
	}
	if len(limits) > 0 {
		label := joinHuman(limits)
		word := "regla"
		if len(limitRules) > 1 {
			word = "reglas"
		}
		return Access{State: FirewallLimited, Limit: label,
			Why: fmt.Sprintf("solo %s (%s %s)", accessFrom(label), word, joinHuman(limitRules))}
	}
	if len(blocked) > 0 {
		return Access{State: FirewallFiltered, Why: strings.Join(blocked, ", ")}
	}
	names := make([]string, 0, 3)
	for _, prof := range fw.Active() {
		names = append(names, prof.Name)
	}
	return Access{State: FirewallFiltered, Why: "ninguna regla lo permite en el perfil " + strings.Join(names, ", ")}
}

// joinHuman une una lista como en español: "A", "A y B", "A, B y C".
func joinHuman(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " y " + xs[len(xs)-1]
}

func accessFrom(label string) string {
	if strings.HasPrefix(label, "desde ") || strings.HasPrefix(label, "hacia ") || strings.HasPrefix(label, "en ") {
		return label
	}
	return "desde " + label
}

// fullBlock devuelve una regla de bloqueo que se aplica al puerto sin
// restricciones de dirección. Las de bloqueo parcial no se tienen en cuenta
// (se peca de considerar el puerto accesible, nunca al revés).
func (fw *Firewall) fullBlock(p Port, profile int) *FirewallRule {
	for i := range fw.Rules {
		r := &fw.Rules[i]
		if r.Allow || !r.matches(p, profile) {
			continue
		}
		if anyAddr(r.Local) && anyAddr(r.Remote) && r.Interfaces == "" && anyIfType(r.IfTypes) {
			return r
		}
	}
	return nil
}

// matches comprueba perfil, protocolo, puerto, programa y servicio.
func (r *FirewallRule) matches(p Port, profile int) bool {
	if r.Profiles&profile == 0 {
		return false
	}
	switch {
	case r.Protocol == 256:
	case r.Protocol == 6 && p.Proto == "tcp":
	case r.Protocol == 17 && p.Proto == "udp":
	default:
		return false
	}
	return matchPorts(r.LocalPorts, p) && matchApp(r.App, p.Process) && matchService(r.Service, p.Services)
}

// limit devuelve la restricción de la regla para este puerto ("" si no la
// tiene) y si la regla llega a aplicarse: una regla limitada a direcciones
// locales no cubre un puerto que solo escucha en otras.
func (r *FirewallRule) limit(p Port) (string, bool) {
	var parts []string
	if !anyAddr(r.Local) {
		local := parseAddrs(r.Local)
		if specific := specificAddrs(p.Addresses); len(specific) > 0 && !local.containsAny(specific) {
			return "", false
		}
		parts = append(parts, local.describe(true))
	}
	if !anyAddr(r.Remote) {
		parts = append(parts, parseAddrs(r.Remote).describe(false))
	}
	if r.Interfaces != "" {
		parts = append(parts, "en la interfaz "+r.Interfaces)
	} else if !anyIfType(r.IfTypes) {
		parts = append(parts, "en "+ifTypesLabel(r.IfTypes))
	}
	return strings.Join(parts, ", "), true
}

func anyAddr(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || s == "*"
}

func anyIfType(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	return s == "" || s == "all"
}

func ifTypesLabel(s string) string {
	names := map[string]string{"lan": "red cableada", "wireless": "wifi", "remoteaccess": "conexiones VPN o de acceso remoto"}
	var out []string
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if n, ok := names[strings.ToLower(t)]; ok {
			out = append(out, n)
		} else if t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, " y ")
}

// specificAddrs devuelve las direcciones de escucha que no son comodines.
// Si el puerto escucha en todas (0.0.0.0, ::), devuelve nil.
func specificAddrs(addrs []string) []net.IP {
	var out []net.IP
	for _, a := range addrs {
		a = strings.Trim(a, "[]")
		if i := strings.IndexByte(a, '%'); i >= 0 {
			a = a[:i]
		}
		ip := net.ParseIP(a)
		if ip == nil || ip.IsUnspecified() {
			return nil
		}
		out = append(out, ip)
	}
	return out
}

// addrSet es una lista de direcciones de una regla del firewall: IPs,
// subredes (CIDR o con máscara), rangos y palabras clave (LocalSubnet…).
type addrSet struct {
	nets     []*net.IPNet
	ranges   [][2]net.IP
	keywords []string
	raw      []string
}

func parseAddrs(s string) addrSet {
	var set addrSet
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" || tok == "*" {
			continue
		}
		set.raw = append(set.raw, tok)
		if lo, hi, ok := strings.Cut(tok, "-"); ok {
			a, b := net.ParseIP(lo), net.ParseIP(hi)
			if a != nil && b != nil {
				set.ranges = append(set.ranges, [2]net.IP{a, b})
				continue
			}
		}
		if ip, mask, ok := strings.Cut(tok, "/"); ok {
			if _, n, err := net.ParseCIDR(tok); err == nil {
				set.nets = append(set.nets, n)
				continue
			}
			if base, m := net.ParseIP(ip), net.ParseIP(mask); base != nil && m != nil && m.To4() != nil {
				mm := net.IPMask(m.To4())
				set.nets = append(set.nets, &net.IPNet{IP: base.Mask(mm), Mask: mm})
				continue
			}
		}
		if ip := net.ParseIP(tok); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			set.nets = append(set.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		set.keywords = append(set.keywords, tok)
	}
	return set
}

func (s addrSet) contains(ip net.IP) bool {
	if len(s.keywords) > 0 {
		return true // LocalSubnet, DHCP…: no se puede saber, se asume que sí
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, r := range s.ranges {
		a, b, x := r[0].To16(), r[1].To16(), ip.To16()
		if bytes.Compare(x, a) >= 0 && bytes.Compare(x, b) <= 0 {
			return true
		}
	}
	return false
}

func (s addrSet) containsAny(ips []net.IP) bool {
	for _, ip := range ips {
		if s.contains(ip) {
			return true
		}
	}
	return false
}

var (
	_, tailscale4, _ = net.ParseCIDR("100.64.0.0/10")
	_, tailscale6, _ = net.ParseCIDR("fd7a:115c:a1e0::/48")
)

// describe resume la lista para mostrarla: "Tailscale", "red local" o las
// direcciones. local indica si son direcciones de destino del equipo.
func (s addrSet) describe(local bool) string {
	if len(s.raw) == 0 {
		return ""
	}
	ts := len(s.keywords) == 0 && len(s.ranges) == 0
	for _, n := range s.nets {
		if !(tailscale4.Contains(n.IP) || tailscale6.Contains(n.IP)) {
			ts = false
		}
	}
	if ts {
		return "Tailscale"
	}
	if len(s.keywords) == 1 && len(s.raw) == 1 && strings.EqualFold(s.keywords[0], "LocalSubnet") {
		return "la red local"
	}
	list := strings.Join(s.raw, ", ")
	if len(s.raw) > 3 {
		list = strings.Join(s.raw[:3], ", ") + "…"
	}
	if local {
		return "hacia " + list
	}
	return "desde " + list
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
