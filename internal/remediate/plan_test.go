package remediate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/engine"
	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// Sistema simulado: un almacén clave/valor que leen el probe y el remediador.
var (
	memMu  sync.Mutex
	memSys = map[string]string{}
)

func memGet(k string) (string, bool) {
	memMu.Lock()
	defer memMu.Unlock()
	v, ok := memSys[k]
	return v, ok
}
func memSet(k, v string) { memMu.Lock(); defer memMu.Unlock(); memSys[k] = v }
func memDel(k string)    { memMu.Lock(); defer memMu.Unlock(); delete(memSys, k) }

type memProbe struct{}

func (memProbe) Name() string         { return "memval" }
func (memProbe) DefaultField() string { return "value" }
func (memProbe) Collect(_ context.Context, p probes.Params) (probes.Observation, error) {
	v, ok := memGet(p.String("key"))
	if !ok {
		return probes.Observation{Found: false}, nil
	}
	return probes.Observation{Found: true, Fields: map[string]any{"value": v}}, nil
}

// memSetter escribe en el almacén. "broken" falla al aplicar; "noop" no hace nada.
type memSetter struct{}

func (memSetter) Type() string { return "mem.set" }
func (memSetter) Capture(_ context.Context, p probes.Params) (State, error) {
	v, ok := memGet(p.String("key"))
	return State{"exists": ok, "value": v}, nil
}
func (memSetter) Describe(p probes.Params, b State) string { return p.String("key") }
func (memSetter) Apply(_ context.Context, p probes.Params) error {
	switch p.String("mode") {
	case "broken":
		memSet(p.String("key"), "a-medias")
		return errors.New("fallo simulado")
	case "noop":
		return nil
	}
	memSet(p.String("key"), p.String("value"))
	return nil
}
func (memSetter) Restore(_ context.Context, p probes.Params, b State) error {
	if ok, _ := b["exists"].(bool); !ok {
		memDel(p.String("key"))
		return nil
	}
	memSet(p.String("key"), b["value"].(string))
	return nil
}

func init() {
	probes.Register(memProbe{})
	Register(memSetter{})
}

func memRule(id, key, want, risk, safety string, acts ...rule.Action) *rule.Rule {
	return &rule.Rule{ID: id, Title: id, Severity: rule.SevHigh, Category: "test",
		Check:       rule.Check{Probe: "memval", Op: "eq", Expected: want, Params: map[string]any{"key": key}},
		Remediation: rule.Remediation{Summary: "x", BreakingRisk: risk, Safety: safety, Actions: acts}}
}

func act(key, value, mode string) rule.Action {
	return rule.Action{Type: "mem.set", Params: map[string]any{"key": key, "value": value, "mode": mode}}
}

func newExecutor(t *testing.T) (*Executor, *Store) {
	st := &Store{Dir: t.TempDir()}
	verify := func(ctx context.Context, r *rule.Rule) engine.Result {
		return engine.New().Run(ctx, []*rule.Rule{r}, nil)[0]
	}
	return &Executor{Store: st, Verify: verify}, st
}

func TestHardenCycle(t *testing.T) {
	memSys = map[string]string{"a": "0", "c": "0", "d": "0"}
	rules := []*rule.Rule{
		memRule("T-A-001", "a", "1", "low", "", act("a", "1", "")),              // se aplica y verifica
		memRule("T-B-001", "b", "1", "low", "", act("b", "1", "")),              // no existía
		memRule("T-C-001", "c", "1", "low", "", act("c", "1", "broken")),        // falla al aplicar
		memRule("T-D-001", "d", "1", "low", "", act("d", "1", "noop")),          // no surte efecto
		memRule("T-E-001", "e", "1", "high", "", act("e", "1", "")),             // ola 3
		memRule("T-F-001", "f", "1", "low", "remote-access", act("f", "1", "")), // acceso remoto
		memRule("T-G-001", "g", "1", "low", ""),                                 // manual
	}
	ctx := context.Background()
	results := engine.New().Run(ctx, rules, nil)
	items := BuildPlan(ctx, results, Options{Wave: 1})

	status := map[string]ItemStatus{}
	for _, it := range items {
		status[it.Rule.ID] = it.Status
	}
	want := map[string]ItemStatus{"T-A-001": ItemPlanned, "T-B-001": ItemPlanned, "T-C-001": ItemPlanned,
		"T-D-001": ItemPlanned, "T-E-001": ItemWave, "T-F-001": ItemRemote, "T-G-001": ItemManual}
	for id, w := range want {
		if status[id] != w {
			t.Errorf("%s: estado %q, quiero %q", id, status[id], w)
		}
	}

	x, st := newExecutor(t)
	m, err := x.Execute(ctx, st.NewManifest("h", "p", "test", 1), items)
	if err != nil {
		t.Fatal(err)
	}
	outcome := map[string]string{}
	for _, it := range items {
		outcome[it.Rule.ID] = it.Outcome
	}
	if outcome["T-A-001"] != OutcomeVerified || outcome["T-B-001"] != OutcomeVerified {
		t.Errorf("A/B deberían verificarse: %v", outcome)
	}
	if outcome["T-C-001"] != OutcomeFailed || outcome["T-D-001"] != OutcomeNotEffective {
		t.Errorf("C debería fallar y D no surtir efecto: %v", outcome)
	}
	if v, _ := memGet("c"); v != "0" {
		t.Errorf("C debe quedar restaurado a 0 tras el fallo, es %q", v)
	}
	if m.Status != StatusPartial {
		t.Errorf("estado del cambio %q, quiero partial", m.Status)
	}
	if v, _ := memGet("a"); v != "1" {
		t.Fatalf("a = %q tras aplicar", v)
	}

	// Rollback desde el manifiesto guardado en disco (como haría otro proceso).
	loaded, err := st.Load(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := Rollback(ctx, loaded, nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := memGet("a"); v != "0" {
		t.Errorf("rollback: a = %q, quiero 0", v)
	}
	if _, ok := memGet("b"); ok {
		t.Error("rollback: b no existía y debe eliminarse")
	}
	if loaded.Status != StatusRolledBack {
		t.Errorf("estado tras rollback %q", loaded.Status)
	}
	if _, err := st.Latest(); err == nil {
		t.Error("no debería quedar nada que deshacer")
	}
}

func TestRemoteAccessNotConfirmed(t *testing.T) {
	memSys = map[string]string{"r": "0"}
	rules := []*rule.Rule{memRule("T-R-001", "r", "1", "low", "remote-access", act("r", "1", ""))}
	ctx := context.Background()
	items := BuildPlan(ctx, engine.New().Run(ctx, rules, nil), Options{Wave: 1, IncludeRemote: true})
	x, st := newExecutor(t)
	armed := ""
	x.ArmDeadman = func(id string, _ time.Duration) error { armed = id; return nil }
	x.ConfirmRemote = func(time.Duration) bool { return false }
	x.DeadmanTimeout = 30 * time.Second
	m, err := x.Execute(ctx, st.NewManifest("h", "p", "test", 1), items)
	if err != nil {
		t.Fatal(err)
	}
	if armed != m.ID {
		t.Error("el dead-man switch debe armarse antes de aplicar")
	}
	if v, _ := memGet("r"); v != "0" {
		t.Errorf("sin confirmación el cambio debe revertirse, r = %q", v)
	}
	if items[0].Outcome != OutcomeReverted {
		t.Errorf("outcome %q", items[0].Outcome)
	}
}

func TestDeadmanRevertsUnconfirmed(t *testing.T) {
	memSys = map[string]string{"r": "0"}
	rules := []*rule.Rule{memRule("T-R-001", "r", "1", "low", "remote-access", act("r", "1", ""))}
	ctx := context.Background()
	items := BuildPlan(ctx, engine.New().Run(ctx, rules, nil), Options{Wave: 1, IncludeRemote: true})
	x, st := newExecutor(t)
	// Simula que la sesión se corta: nadie confirma ni revierte en el proceso principal.
	x.ArmDeadman = func(string, time.Duration) error { return nil }
	x.ConfirmRemote = func(time.Duration) bool { select {} }
	x.DeadmanTimeout = 50 * time.Millisecond
	m := st.NewManifest("h", "p", "test", 1)
	go x.Execute(ctx, m, items) //nolint:errcheck // el proceso "muere" esperando
	time.Sleep(20 * time.Millisecond)
	if err := RunDeadman(ctx, st, m.ID, time.Second); err != nil {
		t.Fatal(err)
	}
	if v, _ := memGet("r"); v != "0" {
		t.Errorf("el dead-man switch debe revertir, r = %q", v)
	}
	loaded, _ := st.Load(m.ID)
	if !loaded.DeadmanFired {
		t.Error("debe constar que saltó el dead-man switch")
	}
}

func TestGPOManagedSkipped(t *testing.T) {
	memSys = map[string]string{"k": "0"}
	r := memRule("T-P-001", "k", "1", "low", "",
		rule.Action{Type: "registry.set", Params: map[string]any{"path": `HKLM\SOFTWARE\Policies\X`, "name": "Y", "value": 1}})
	ctx := context.Background()
	items := BuildPlan(ctx, engine.New().Run(ctx, []*rule.Rule{r}, nil), Options{Wave: 1, DomainJoined: true})
	if items[0].Status != ItemGPO {
		t.Errorf("estado %q, quiero gpo", items[0].Status)
	}
}

func TestValidateAction(t *testing.T) {
	ok := []rule.Action{
		{Type: "registry.set", Params: map[string]any{"path": `HKLM\SOFTWARE\X`, "name": "Y", "value": 1}},
		{Type: "secpol.set", Params: map[string]any{"section": "System Access", "key": "MinimumPasswordLength", "value": 14}},
		{Type: "auditpol.set", Params: map[string]any{"guid": "0CCE922B-69AE-11D9-BED3-505054503030", "success": true}},
		{Type: "defender.asr", Params: map[string]any{"guid": "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "mode": "block"}},
		{Type: "sysctl.set", Params: map[string]any{"key": "net.ipv4.conf.all.rp_filter", "value": 1}},
		{Type: "sshd.set", Params: map[string]any{"key": "PermitRootLogin", "value": "no"}},
		{Type: "file.mode", Params: map[string]any{"path": "/etc/shadow", "mode": "0640", "group": []any{"shadow", "root"}}},
		{Type: "sudoers.defaults", Params: map[string]any{"option": "use_pty"}},
		{Type: "firewall.remote_address", Params: map[string]any{"rule": `TCP Query User{AAB2B01C-3855-4816-88B1-0F4AB4DC07A0}C:\program files\ninjatrader 8\bin\ninjatrader.exe`, "remote": "LocalSubnet"}},
		{Type: "firewall.remote_address", Params: map[string]any{"rule": "RemoteDesktop-UserMode-In-TCP", "remote": "LocalSubnet"}},
	}
	for _, a := range ok {
		if err := ValidateAction(a); err != nil {
			t.Errorf("%s debería ser válida: %v", a.Type, err)
		}
	}
	bad := []rule.Action{
		{Type: "exec", Params: map[string]any{"cmd": "rm -rf /"}},
		{Type: "registry.set", Params: map[string]any{"path": `HKCU\X`, "name": "Y", "value": 1}},
		{Type: "secpol.set", Params: map[string]any{"section": "System Access", "key": "NewAdministratorName", "value": 1}},
		{Type: "defender.asr", Params: map[string]any{"guid": "x; Remove-Item C:\\", "mode": "block"}},
		{Type: "defender.pref", Params: map[string]any{"name": "DisableRealtimeMonitoring", "value": 1}},
		{Type: "sshd.set", Params: map[string]any{"key": "PermitRootLogin", "value": "no\nPasswordAuthentication yes"}},
		{Type: "sshd.set", Params: map[string]any{"key": "Match", "value": "all"}},
		{Type: "sysctl.set", Params: map[string]any{"key": "../../etc/passwd", "value": 1}},
		{Type: "file.kv_set", Params: map[string]any{"path": "/root/.bashrc", "key": "X", "value": "y"}},
		{Type: "sudoers.defaults", Params: map[string]any{"option": "!authenticate"}},
		{Type: "firewall.remote_address", Params: map[string]any{"rule": "RemoteDesktop-UserMode-In-TCP", "remote": "Any"}},
		{Type: "firewall.remote_address", Params: map[string]any{"rule": "x\n'; Remove-Item C:\\", "remote": "LocalSubnet"}},
		{Type: "firewall.remote_address", Params: map[string]any{"rule": " ", "remote": "LocalSubnet"}},
	}
	for _, a := range bad {
		if err := ValidateAction(a); err == nil {
			t.Errorf("%s %v debería rechazarse", a.Type, a.Params)
		}
	}
}

func TestPlanRule(t *testing.T) {
	memSet("plan.k", "a")
	it := PlanRule(context.Background(), memRule("SURF-X", "plan.k", "b", "low", "", act("plan.k", "b", "")))
	if it.Status != ItemPlanned || len(it.Steps) != 1 || it.Steps[0].Before["value"] != "a" {
		t.Errorf("elemento: %+v", it)
	}
	it = PlanRule(context.Background(), memRule("SURF-Y", "plan.k", "b", "low", "", rule.Action{Type: "no.existe"}))
	if it.Status != ItemUnsupported {
		t.Errorf("acción desconocida: %+v", it)
	}
}
