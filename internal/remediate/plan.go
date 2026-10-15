package remediate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/engine"
	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// ItemStatus clasifica un control fallido dentro del plan.
type ItemStatus string

const (
	ItemPlanned      ItemStatus = "planned"       // se aplicará
	ItemManual       ItemStatus = "manual"        // sin acción automática
	ItemWave         ItemStatus = "wave"          // requiere una ola superior
	ItemRemote       ItemStatus = "remote"        // acceso remoto: requiere --include-remote
	ItemGPO          ItemStatus = "gpo"           // gestionado por una GPO de dominio
	ItemUnsupported  ItemStatus = "unsupported"   // acción no disponible en esta plataforma
	ItemCaptureError ItemStatus = "capture-error" // no se pudo leer el estado previo
	ItemNothing      ItemStatus = "nothing"       // todas las acciones se omiten
)

// Resultados de la ejecución de un elemento.
const (
	OutcomeVerified     = "verified"      // aplicado y verificado
	OutcomeFailed       = "failed"        // error al aplicar: revertido
	OutcomeNotEffective = "not-effective" // aplicado pero el control sigue fallando: revertido
	OutcomeReverted     = "reverted"      // revertido (acceso remoto no confirmado)
)

// Step es una acción del plan con su estado previo.
type Step struct {
	Action rule.Action
	Rem    Remediator
	Before State
	Desc   string
}

// Item es un control fallido y lo que Bastion hará con él.
type Item struct {
	Rule    *rule.Rule
	Eval    engine.Result
	Status  ItemStatus
	Reason  string
	Steps   []*Step
	Outcome string
	Message string
}

// Remote indica si el elemento puede afectar al acceso remoto.
func (it *Item) Remote() bool { return it.Rule.Remediation.Safety == "remote-access" }

// Options controla qué se incluye en el plan.
type Options struct {
	Wave          int  // 1: riesgo ninguno/bajo · 2: +medio · 3: +alto
	IncludeRemote bool // incluir cambios que afectan al acceso remoto
	ForceLocal    bool // aplicar aunque el valor lo gestione una GPO de dominio
	DomainJoined  bool
}

// BuildPlan clasifica los controles fallidos y captura el estado previo de
// los que se van a aplicar (solo lectura).
func BuildPlan(ctx context.Context, results []engine.Result, o Options) []*Item {
	var items []*Item
	for _, res := range results {
		if res.Status != engine.Fail {
			continue
		}
		r := res.Rule
		it := &Item{Rule: r, Eval: res}
		items = append(items, it)
		acts := r.Remediation.Actions
		switch {
		case len(acts) == 0:
			it.Status, it.Reason = ItemManual, "sin acción automática: sigue la remediación manual"
			continue
		case rule.RiskWave(r.Remediation.BreakingRisk) > o.Wave:
			it.Status = ItemWave
			it.Reason = fmt.Sprintf("riesgo de rotura %s: requiere --wave %d", riskNames[r.Remediation.BreakingRisk], rule.RiskWave(r.Remediation.BreakingRisk))
			continue
		case it.Remote() && !o.IncludeRemote:
			it.Status, it.Reason = ItemRemote, "puede cortar el acceso remoto: requiere --include-remote (con dead-man switch)"
			continue
		case o.DomainJoined && !o.ForceLocal && managedByPolicy(acts):
			it.Status, it.Reason = ItemGPO, "equipo unido a dominio y valor de directiva: corrígelo en la GPO (o usa --force-local)"
			continue
		}
		it.Status = ItemPlanned
		skipped := 0
		for _, a := range acts {
			rem, ok := Get(a.Type)
			if !ok {
				it.Status, it.Reason = ItemUnsupported, "la acción "+a.Type+" no está disponible en esta plataforma"
				break
			}
			p := probes.Params(a.Params)
			before, err := rem.Capture(ctx, p)
			if err != nil {
				it.Status, it.Reason = ItemCaptureError, "no se pudo leer el estado previo: "+err.Error()
				break
			}
			if Skipped(before) {
				skipped++
			}
			it.Steps = append(it.Steps, &Step{Action: a, Rem: rem, Before: before, Desc: rem.Describe(p, before)})
		}
		if it.Status == ItemPlanned && skipped == len(acts) {
			it.Status, it.Reason = ItemNothing, "no hay nada que cambiar en este equipo"
		}
	}
	return items
}

var riskNames = map[string]string{"none": "ninguno", "low": "bajo", "medium": "medio", "high": "alto"}

// managedByPolicy detecta valores de directiva (claves ...\Policies\...),
// que una GPO de dominio volvería a sobrescribir.
func managedByPolicy(acts []rule.Action) bool {
	for _, a := range acts {
		if a.Type == "registry.set" && strings.Contains(strings.ToLower(fmt.Sprint(a.Params["path"])), `\policies\`) {
			return true
		}
	}
	return false
}

// Event informa del progreso de la ejecución.
type Event struct {
	Kind string // item-start, verified, failed, not-effective, remote-phase, remote-confirmed, remote-reverted
	Item *Item
	Err  error
}

// Executor aplica un plan de forma transaccional.
type Executor struct {
	Store  *Store
	Verify func(ctx context.Context, r *rule.Rule) engine.Result
	Events func(Event)
	// ConfirmRemote pide confirmación de que el acceso remoto sigue
	// funcionando. Si es nil, los cambios remotos no se confirman (laboratorios).
	ConfirmRemote  func(timeout time.Duration) bool
	ArmDeadman     func(id string, timeout time.Duration) error
	DeadmanTimeout time.Duration
}

func (x *Executor) emit(kind string, it *Item, err error) {
	if x.Events != nil {
		x.Events(Event{Kind: kind, Item: it, Err: err})
	}
}

// Execute aplica los elementos planificados y devuelve el manifiesto.
func (x *Executor) Execute(ctx context.Context, m *Manifest, items []*Item) (*Manifest, error) {
	if err := m.Save(); err != nil {
		return nil, fmt.Errorf("no se pudo crear la instantánea: %w", err)
	}
	var normal, remote []*Item
	for _, it := range items {
		if it.Status != ItemPlanned {
			continue
		}
		if it.Remote() {
			remote = append(remote, it)
		} else {
			normal = append(normal, it)
		}
	}
	for _, it := range normal {
		x.applyItem(ctx, m, it, false)
	}

	if len(remote) > 0 {
		x.emit("remote-phase", nil, nil)
		if x.ConfirmRemote != nil && x.ArmDeadman != nil {
			deadline := time.Now().Add(x.DeadmanTimeout).UTC()
			m.DeadmanDeadline = &deadline
			if err := m.Save(); err != nil {
				return m, err
			}
			if err := x.ArmDeadman(m.ID, x.DeadmanTimeout); err != nil {
				// Sin red de seguridad no se tocan los accesos remotos.
				for _, it := range remote {
					it.Outcome, it.Message = OutcomeFailed, "no se pudo armar el dead-man switch: "+err.Error()
				}
				remote = nil
			}
		}
		applied := false
		for _, it := range remote {
			x.applyItem(ctx, m, it, true)
			applied = applied || it.Outcome == OutcomeVerified
		}
		switch {
		case !applied || x.ConfirmRemote == nil:
			m.Confirmed = true
		case x.ConfirmRemote(x.DeadmanTimeout - 15*time.Second):
			m.Confirmed = true
			x.emit("remote-confirmed", nil, nil)
		default:
			x.rollbackFiltered(ctx, m, func(e *Entry) bool { return e.RemoteAccess })
			for _, it := range remote {
				if it.Outcome == OutcomeVerified {
					it.Outcome, it.Message = OutcomeReverted, "acceso remoto no confirmado a tiempo"
				}
			}
			x.emit("remote-reverted", nil, nil)
		}
		_ = m.Save()
	}

	verified, failed := 0, 0
	for _, it := range items {
		if it.Status != ItemPlanned {
			continue
		}
		m.Rules = append(m.Rules, RuleOutcome{RuleID: it.Rule.ID, Title: it.Rule.Title, Outcome: it.Outcome, Message: it.Message})
		if it.Outcome == OutcomeVerified {
			verified++
			if it.Rule.Remediation.RebootRequired {
				m.RebootRequired = true
			}
		} else {
			failed++
		}
	}
	switch {
	case verified == 0 && failed == 0:
		m.Status = StatusNothing
	case verified == 0:
		m.Status = StatusFailed
	case failed > 0:
		m.Status = StatusPartial
	default:
		m.Status = StatusApplied
	}
	return m, m.Save()
}

func (x *Executor) applyItem(ctx context.Context, m *Manifest, it *Item, remote bool) {
	x.emit("item-start", it, nil)
	var done []*Entry
	for _, st := range it.Steps {
		p := probes.Params(st.Action.Params)
		// Se vuelve a capturar justo antes de aplicar: el estado guardado es
		// el real en el momento del cambio.
		before, err := st.Rem.Capture(ctx, p)
		if err != nil {
			x.revert(ctx, m, done)
			it.Outcome, it.Message = OutcomeFailed, "no se pudo leer el estado previo: "+err.Error()
			x.emit("failed", it, err)
			return
		}
		if Skipped(before) {
			continue
		}
		e := &Entry{Seq: len(m.Entries) + 1, RuleID: it.Rule.ID, Action: st.Action, Description: st.Rem.Describe(p, before),
			Before: before, RemoteAccess: remote, Attempted: true}
		m.Entries = append(m.Entries, e)
		if err := m.Save(); err != nil {
			it.Outcome, it.Message = OutcomeFailed, "no se pudo guardar la instantánea: "+err.Error()
			x.emit("failed", it, err)
			return
		}
		if err := st.Rem.Apply(ctx, p); err != nil {
			e.Error = err.Error()
			done = append(done, e) // también se restaura: pudo quedar a medias
			x.revert(ctx, m, done)
			it.Outcome, it.Message = OutcomeFailed, err.Error()
			m.store.Log(m.ID, it.Rule.ID, "failed", err.Error())
			x.emit("failed", it, err)
			return
		}
		e.Applied = true
		done = append(done, e)
		_ = m.Save()
	}
	if len(done) == 0 {
		it.Outcome, it.Message = OutcomeNotEffective, "no había nada que cambiar"
		x.emit("not-effective", it, nil)
		return
	}
	res := x.Verify(ctx, it.Rule)
	if res.Status != engine.Pass {
		x.revert(ctx, m, done)
		msg := "el control sigue sin cumplirse"
		if res.Actual != "" {
			msg += " (actual " + res.Actual + ")"
		}
		if res.Message != "" {
			msg += ": " + res.Message
		}
		it.Outcome, it.Message = OutcomeNotEffective, msg+"; cambio revertido"
		m.store.Log(m.ID, it.Rule.ID, "not-effective", msg)
		x.emit("not-effective", it, nil)
		return
	}
	it.Outcome = OutcomeVerified
	m.store.Log(m.ID, it.Rule.ID, "applied", "")
	x.emit("verified", it, nil)
}

// revert restaura entradas en orden inverso.
func (x *Executor) revert(ctx context.Context, m *Manifest, entries []*Entry) {
	for i := len(entries) - 1; i >= 0; i-- {
		restoreEntry(ctx, entries[i])
	}
	_ = m.Save()
}

func (x *Executor) rollbackFiltered(ctx context.Context, m *Manifest, filter func(*Entry) bool) {
	_ = Rollback(ctx, m, filter)
}

func restoreEntry(ctx context.Context, e *Entry) error {
	if e.RolledBack {
		return nil
	}
	rem, ok := Get(e.Action.Type)
	if !ok {
		return fmt.Errorf("la acción %s no está disponible en esta plataforma", e.Action.Type)
	}
	// El manifiesto se lee de disco: se revalida como si fuera una regla.
	if _, known := Specs[e.Action.Type]; known {
		if err := ValidateAction(e.Action); err != nil {
			return fmt.Errorf("acción inválida en el manifiesto: %w", err)
		}
	}
	if err := rem.Restore(ctx, probes.Params(e.Action.Params), e.Before); err != nil {
		e.Error = strings.TrimSpace(e.Error + " · rollback: " + err.Error())
		return err
	}
	e.RolledBack = true
	return nil
}

// Rollback deshace (en orden inverso) las entradas que cumplan filter (o
// todas si es nil) y actualiza el manifiesto.
func Rollback(ctx context.Context, m *Manifest, filter func(*Entry) bool) error {
	var errs []error
	for i := len(m.Entries) - 1; i >= 0; i-- {
		e := m.Entries[i]
		if !e.Attempted || e.RolledBack || (filter != nil && !filter(e)) {
			continue
		}
		if err := restoreEntry(ctx, e); err != nil {
			errs = append(errs, fmt.Errorf("%s (%s): %w", e.RuleID, e.Action.Type, err))
			m.store.Log(m.ID, e.RuleID, "rollback-failed", err.Error())
		} else {
			m.store.Log(m.ID, e.RuleID, "rolled-back", "")
		}
		_ = m.Save()
	}
	if m.pending(nil) == 0 {
		m.Status = StatusRolledBack
	}
	_ = m.Save()
	return errors.Join(errs...)
}

// RunDeadman espera hasta el plazo y, si el acceso remoto no se confirmó,
// deshace los cambios de acceso remoto. Se ejecuta en un proceso separado
// que sobrevive al cierre de la sesión SSH/RDP.
func RunDeadman(ctx context.Context, s *Store, id string, timeout time.Duration) error {
	m, err := s.Load(id)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	if m.DeadmanDeadline != nil {
		deadline = *m.DeadmanDeadline
	}
	select {
	case <-time.After(time.Until(deadline)):
	case <-ctx.Done():
		return ctx.Err()
	}
	if m, err = s.Load(id); err != nil {
		return err
	}
	remote := func(e *Entry) bool { return e.RemoteAccess }
	if m.Confirmed || m.pending(remote) == 0 {
		return nil
	}
	m.DeadmanFired = true
	s.Log(id, "", "deadman", "acceso remoto no confirmado: revirtiendo")
	return Rollback(ctx, m, remote)
}
