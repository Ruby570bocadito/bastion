// Package remediate aplica los cambios de hardening de forma transaccional:
// captura el estado previo, aplica, verifica y revierte si algo falla.
//
// Principios (ver docs/05-remediacion-segura.md y ADR-0004):
//   - Solo existen acciones TIPADAS (registry.set, sysctl.set...). No hay ni
//     habrá un tipo "ejecutar comando".
//   - Los parámetros se validan estrictamente (listas blancas y expresiones
//     regulares) antes de usarse, también en "bastion rules lint".
//   - Cada acción sabe capturar el estado previo y restaurarlo.
package remediate

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// State es el estado previo de un elemento. Se guarda en el manifiesto del
// cambio (JSON) para poder restaurarlo, incluso desde otro proceso.
type State map[string]any

// Remediator aplica y revierte un tipo de acción.
type Remediator interface {
	Type() string
	// Capture lee el estado actual (solo lectura).
	Capture(ctx context.Context, p probes.Params) (State, error)
	// Describe explica el cambio: "elemento: antes → después".
	Describe(p probes.Params, before State) string
	Apply(ctx context.Context, p probes.Params) error
	Restore(ctx context.Context, p probes.Params, before State) error
}

var (
	regMu        sync.RWMutex
	remediators  = map[string]Remediator{}
	errSkipState = "skip"
)

// Register registra un remediador disponible en esta plataforma.
func Register(r Remediator) {
	regMu.Lock()
	defer regMu.Unlock()
	remediators[r.Type()] = r
}

// Get devuelve el remediador de un tipo, si existe en esta plataforma.
func Get(t string) (Remediator, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	r, ok := remediators[t]
	return r, ok
}

// Skipped indica que la captura decidió que no hay nada que hacer (p. ej. un
// parámetro sysctl de IPv6 en un equipo sin IPv6, marcado como optional).
func Skipped(s State) bool { b, _ := s[errSkipState].(bool); return b }

func skipState(reason string) State { return State{errSkipState: true, "reason": reason} }

// ---- Especificación y validación de acciones (independiente del SO) -----

// Spec describe un tipo de acción para validarla en cualquier plataforma.
type Spec struct {
	OS       string
	Required []string
	Validate func(p probes.Params) error
}

var (
	reGUID     = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	reSysctl   = regexp.MustCompile(`^[a-z0-9_]+(\.[a-zA-Z0-9_-]+)+$`)
	reWord     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
	reKVKey    = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	reModule   = regexp.MustCompile(`^[a-z0-9_-]+$`)
	reUnit     = regexp.MustCompile(`^[A-Za-z0-9@._-]+\.(service|socket|timer|path)$`)
	reService  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	reOctal    = regexp.MustCompile(`^0?[0-7]{3,4}$`)
	reAccount  = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)
	reSafeText = regexp.MustCompile(`^[^\r\n\x00]*$`)
)

// SecpolKeys son las claves de [System Access] que Bastion puede modificar.
var SecpolKeys = map[string]bool{
	"MinimumPasswordLength": true, "PasswordComplexity": true, "PasswordHistorySize": true,
	"MaximumPasswordAge": true, "MinimumPasswordAge": true, "ClearTextPassword": true,
	"LockoutBadCount": true, "LockoutDuration": true, "ResetLockoutCount": true,
	"EnableGuestAccount": true, "LSAAnonymousNameLookup": true,
}

// DefenderPrefs son las preferencias de Defender que Bastion puede modificar.
var DefenderPrefs = map[string]bool{
	"PUAProtection": true, "MAPSReporting": true, "EnableNetworkProtection": true, "SubmitSamplesConsent": true,
}

// ASRModes traduce el modo de una regla ASR a su valor numérico.
var ASRModes = map[string]int{"disabled": 0, "block": 1, "audit": 2, "warn": 6}

// SudoersOptions son las opciones "Defaults" que Bastion puede añadir.
var SudoersOptions = map[string]bool{
	"use_pty": true, `logfile="/var/log/sudo.log"`: true,
}

// Specs son todos los tipos de acción conocidos.
var Specs = map[string]Spec{
	"registry.set": {OS: "windows", Required: []string{"path", "name", "value"}, Validate: func(p probes.Params) error {
		path := strings.ToUpper(p.String("path"))
		if !strings.HasPrefix(path, `HKLM\`) && !strings.HasPrefix(path, `HKEY_LOCAL_MACHINE\`) {
			return fmt.Errorf("solo se admiten rutas HKLM")
		}
		switch strings.ToUpper(p.String("value_type")) {
		case "", "DWORD", "QWORD":
			if _, err := intParam(p, "value"); err != nil && strings.ToUpper(p.String("value_type")) != "" {
				return err
			}
		case "SZ":
		default:
			return fmt.Errorf("value_type %q no soportado (DWORD, QWORD, SZ)", p.String("value_type"))
		}
		return safeText(p, "path", "name", "value")
	}},
	"secpol.set": {OS: "windows", Required: []string{"section", "key", "value"}, Validate: func(p probes.Params) error {
		if p.String("section") != "System Access" {
			return fmt.Errorf("solo se admite la sección \"System Access\"")
		}
		if !SecpolKeys[p.String("key")] {
			return fmt.Errorf("clave %q no permitida", p.String("key"))
		}
		_, err := intParam(p, "value")
		return err
	}},
	"auditpol.set": {OS: "windows", Required: []string{"guid"}, Validate: func(p probes.Params) error {
		if !reGUID.MatchString(p.String("guid")) {
			return fmt.Errorf("guid inválido")
		}
		if !p.Bool("success", false) && !p.Bool("failure", false) {
			return fmt.Errorf("indica success y/o failure")
		}
		return nil
	}},
	"service.config": {OS: "windows", Required: []string{"name", "start_type"}, Validate: func(p probes.Params) error {
		if !reService.MatchString(p.String("name")) {
			return fmt.Errorf("nombre de servicio inválido")
		}
		switch p.String("start_type") {
		case "disabled", "manual", "auto":
			return nil
		}
		return fmt.Errorf("start_type debe ser disabled, manual o auto")
	}},
	"defender.asr": {OS: "windows", Required: []string{"guid", "mode"}, Validate: func(p probes.Params) error {
		if !reGUID.MatchString(p.String("guid")) {
			return fmt.Errorf("guid inválido")
		}
		if _, ok := ASRModes[p.String("mode")]; !ok {
			return fmt.Errorf("mode debe ser block, audit, warn o disabled")
		}
		return nil
	}},
	"defender.pref": {OS: "windows", Required: []string{"name", "value"}, Validate: func(p probes.Params) error {
		if !DefenderPrefs[p.String("name")] {
			return fmt.Errorf("preferencia %q no permitida", p.String("name"))
		}
		v, err := intParam(p, "value")
		if err != nil || v < 0 || v > 6 {
			return fmt.Errorf("value debe ser un entero entre 0 y 6")
		}
		return nil
	}},
	"sysctl.set": {OS: "linux", Required: []string{"key", "value"}, Validate: func(p probes.Params) error {
		if !reSysctl.MatchString(p.String("key")) || strings.Contains(p.String("key"), "..") {
			return fmt.Errorf("clave sysctl inválida")
		}
		return safeText(p, "value")
	}},
	"sshd.set": {OS: "linux", Required: []string{"key", "value"}, Validate: func(p probes.Params) error {
		if !reWord.MatchString(p.String("key")) {
			return fmt.Errorf("opción de sshd inválida")
		}
		if strings.ToLower(p.String("key")) == "include" || strings.ToLower(p.String("key")) == "match" {
			return fmt.Errorf("Include y Match no se pueden gestionar")
		}
		return safeText(p, "value")
	}},
	"kmod.block": {OS: "linux", Required: []string{"name"}, Validate: func(p probes.Params) error {
		if !reModule.MatchString(p.String("name")) {
			return fmt.Errorf("nombre de módulo inválido")
		}
		return nil
	}},
	"systemd.disable": {OS: "linux", Required: []string{"unit"}, Validate: func(p probes.Params) error {
		if !reUnit.MatchString(p.String("unit")) {
			return fmt.Errorf("unidad inválida")
		}
		return nil
	}},
	"file.mode": {OS: "linux", Required: []string{"path", "mode"}, Validate: func(p probes.Params) error {
		for _, path := range p.Strings("path") {
			if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
				return fmt.Errorf("ruta %q no absoluta", path)
			}
		}
		if !reOctal.MatchString(p.String("mode")) {
			return fmt.Errorf("mode debe ser octal, p. ej. \"0600\"")
		}
		for _, k := range []string{"owner", "group"} {
			for _, v := range p.Strings(k) {
				if !reAccount.MatchString(v) {
					return fmt.Errorf("%s %q inválido", k, v)
				}
			}
		}
		return nil
	}},
	"file.kv_set": {OS: "linux", Required: []string{"path", "key", "value"}, Validate: func(p probes.Params) error {
		if !strings.HasPrefix(p.String("path"), "/etc/") || strings.Contains(p.String("path"), "..") {
			return fmt.Errorf("solo se admiten ficheros bajo /etc")
		}
		if !reKVKey.MatchString(p.String("key")) {
			return fmt.Errorf("clave inválida")
		}
		return safeText(p, "value", "separator")
	}},
	// Limita a la red local una regla del Firewall de Windows por su nombre
	// interno (lo usa "bastion surface fix", no las reglas del catálogo).
	"firewall.remote_address": {OS: "windows", Required: []string{"rule", "remote"}, Validate: func(p probes.Params) error {
		if p.String("remote") != "LocalSubnet" {
			return fmt.Errorf("remote solo admite LocalSubnet")
		}
		if r := p.String("rule"); strings.TrimSpace(r) == "" || len(r) > 1024 {
			return fmt.Errorf("rule debe ser el nombre interno de una regla del firewall")
		}
		return safeText(p, "rule")
	}},
	"sudoers.defaults": {OS: "linux", Required: []string{"option"}, Validate: func(p probes.Params) error {
		if !SudoersOptions[p.String("option")] {
			return fmt.Errorf("opción %q no permitida", p.String("option"))
		}
		return nil
	}},
}

// ValidateAction comprueba el tipo y los parámetros de una acción.
func ValidateAction(a rule.Action) error {
	spec, ok := Specs[a.Type]
	if !ok {
		types := make([]string, 0, len(Specs))
		for t := range Specs {
			types = append(types, t)
		}
		sort.Strings(types)
		return fmt.Errorf("tipo desconocido (válidos: %s)", strings.Join(types, ", "))
	}
	p := probes.Params(a.Params)
	if err := p.Require(spec.Required...); err != nil {
		return err
	}
	if spec.Validate != nil {
		return spec.Validate(p)
	}
	return nil
}

func safeText(p probes.Params, keys ...string) error {
	for _, k := range keys {
		for _, v := range p.Strings(k) {
			if !reSafeText.MatchString(v) {
				return fmt.Errorf("%s contiene saltos de línea o caracteres no permitidos", k)
			}
		}
	}
	return nil
}

// intParam lee un parámetro entero (YAML lo entrega como int; JSON, como float64).
func intParam(p probes.Params, key string) (int64, error) {
	switch v := p[key].(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case uint64:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err == nil {
			return n, nil
		}
	}
	return 0, fmt.Errorf("%s debe ser un número entero", key)
}

// textOf representa un valor de estado para Describe.
func textOf(v any) string {
	switch x := v.(type) {
	case nil:
		return "—"
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
	}
	return fmt.Sprint(v)
}
