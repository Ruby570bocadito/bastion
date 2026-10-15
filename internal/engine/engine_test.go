package engine

import (
	"context"
	"testing"

	"github.com/tu-usuario/bastion/internal/probes"
	"github.com/tu-usuario/bastion/pkg/rule"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		op       string
		actual   any
		expected any
		want     bool
	}{
		{"eq", "2", 2, true},
		{"eq", uint64(0), 0, true},
		{"eq", "No", "no", true},
		{"eq", true, "True", true},
		{"eq", "False", false, true},
		{"ne", "yes", "no", true},
		{"gte", "14", 14, true},
		{"gte", int64(8), 14, false},
		{"lte", "4", 4, true},
		{"between", 5, []any{1, 5}, true},
		{"between", 0, []any{1, 5}, false},
		{"in", "prohibit-password", []any{"no", "prohibit-password"}, true},
		{"not_in", "enabled", []any{"enabled", "enabled-runtime"}, false},
		{"contains", []any{"rw", "nosuid", "nodev"}, []any{"nodev", "nosuid"}, true},
		{"contains", []any{"rw", "nosuid"}, []any{"nodev", "nosuid"}, false},
		{"contains", []any{1, 2}, 1, true},
		{"not_contains", "aes128-ctr,aes256-cbc", "3des", true},
		{"regex", "aes256-cbc", "cbc", true},
		{"not_regex", "aes256-ctr,chacha20", "(cbc|3des|arcfour)", true},
		{"bits_set", uint64(2147483640), 24, true},
		{"bits_clear", uint64(2147483640), 7, true},
		{"bits_clear", uint64(2147483647), 7, false},
		{"mode_max", "0644", "0600", false},
		{"mode_max", "0600", "0644", true},
		{"mode_max", "0640", "0640", true},
	}
	for _, c := range cases {
		got, err := compare(c.op, c.actual, c.expected)
		if err != nil {
			t.Errorf("%s(%v, %v): error %v", c.op, c.actual, c.expected, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s(%v, %v) = %v, quiero %v", c.op, c.actual, c.expected, got, c.want)
		}
	}
}

func TestCompareErrors(t *testing.T) {
	if _, err := compare("gte", "abc", 3); err == nil {
		t.Error("gte con texto no numérico debería fallar")
	}
	if _, err := compare("regex", "x", "("); err == nil {
		t.Error("regex inválida debería fallar")
	}
}

func TestLookupField(t *testing.T) {
	f := map[string]any{"Domain": map[string]any{"Enabled": "True"}, "a.b": 1}
	if v, ok := lookupField(f, "Domain.Enabled"); !ok || v != "True" {
		t.Errorf("Domain.Enabled = %v, %v", v, ok)
	}
	if v, ok := lookupField(f, "domain.enabled"); !ok || v != "True" {
		t.Errorf("búsqueda sin mayúsculas falló: %v, %v", v, ok)
	}
	if v, ok := lookupField(f, "a.b"); !ok || v != 1 {
		t.Errorf("clave literal con punto: %v, %v", v, ok)
	}
	if _, ok := lookupField(f, "Private.Enabled"); ok {
		t.Error("campo inexistente encontrado")
	}
}

// fakeProbe devuelve observaciones fijas por clave.
type fakeProbe struct{}

func (fakeProbe) Name() string         { return "fake" }
func (fakeProbe) DefaultField() string { return "value" }
func (fakeProbe) Collect(_ context.Context, p probes.Params) (probes.Observation, error) {
	switch p.String("key") {
	case "missing":
		return probes.Observation{Found: false}, nil
	case "na":
		return probes.Observation{}, probes.NotApplicable("no aplica")
	case "list":
		return probes.Observation{Found: true, Fields: map[string]any{"value": []any{uint64(2), uint64(2)}}}, nil
	}
	return probes.Observation{Found: true, Fields: map[string]any{"value": p.String("key")}}, nil
}

func init() { probes.Register(fakeProbe{}) }

func leaf(key, op string, exp any) rule.Check {
	return rule.Check{Probe: "fake", Op: op, Expected: exp, Params: map[string]any{"key": key}}
}

func TestEvalLeafMissing(t *testing.T) {
	e := New()
	ctx := probes.WithSession(context.Background(), probes.NewSession())

	c := leaf("missing", "eq", 0)
	if ev := e.evalCheck(ctx, c); ev.Status != Fail {
		t.Errorf("ausente sin default debería fallar, es %s", ev.Status)
	}
	c.HasDefault, c.Default = true, 0
	if ev := e.evalCheck(ctx, c); ev.Status != Pass {
		t.Errorf("ausente con default 0 debería pasar, es %s (%s)", ev.Status, ev.Message)
	}
	c = leaf("missing", "eq", 0)
	c.OnMissing = "na"
	if ev := e.evalCheck(ctx, c); ev.Status != NA {
		t.Errorf("on_missing na → %s", ev.Status)
	}
	if ev := e.evalCheck(ctx, leaf("na", "eq", 1)); ev.Status != NA {
		t.Errorf("NotApplicable → %s", ev.Status)
	}
	if ev := e.evalCheck(ctx, leaf("missing", "absent", nil)); ev.Status != Pass {
		t.Errorf("absent → %s", ev.Status)
	}
}

func TestEvalEach(t *testing.T) {
	e := New()
	ctx := probes.WithSession(context.Background(), probes.NewSession())
	c := leaf("list", "eq", 2)
	c.Each = "all"
	if ev := e.evalCheck(ctx, c); ev.Status != Pass {
		t.Errorf("each all → %s (%s)", ev.Status, ev.Message)
	}
}

func TestEvalComposite(t *testing.T) {
	e := New()
	ctx := probes.WithSession(context.Background(), probes.NewSession())
	all := rule.Check{All: []rule.Check{leaf("a", "eq", "a"), leaf("b", "eq", "x")}}
	if ev := e.evalCheck(ctx, all); ev.Status != Fail {
		t.Errorf("all con un fallo → %s", ev.Status)
	}
	anyC := rule.Check{Any: []rule.Check{leaf("a", "eq", "x"), leaf("b", "eq", "b")}}
	if ev := e.evalCheck(ctx, anyC); ev.Status != Pass {
		t.Errorf("any con un acierto → %s", ev.Status)
	}
	allNA := rule.Check{All: []rule.Check{leaf("na", "eq", 1), leaf("na", "eq", 1)}}
	if ev := e.evalCheck(ctx, allNA); ev.Status != NA {
		t.Errorf("all de NA → %s", ev.Status)
	}
	mixed := rule.Check{All: []rule.Check{leaf("a", "eq", "a"), leaf("na", "eq", 1)}}
	if ev := e.evalCheck(ctx, mixed); ev.Status != Pass {
		t.Errorf("all pass + NA → %s", ev.Status)
	}
}

func TestScore(t *testing.T) {
	crit := &rule.Rule{ID: "T-X-1", Severity: rule.SevCritical, Category: "A"}
	low := &rule.Rule{ID: "T-X-2", Severity: rule.SevLow, Category: "B"}
	na := &rule.Rule{ID: "T-X-3", Severity: rule.SevHigh, Category: "B"}
	s := ComputeScore([]Result{
		{Rule: crit, Eval: Eval{Status: Pass}},
		{Rule: low, Eval: Eval{Status: Fail}},
		{Rule: na, Eval: Eval{Status: NA}},
	})
	if s.Value != 91 { // 10 / 11
		t.Errorf("score = %d, quiero 91", s.Value)
	}
	if s.Grade != "A" || s.Passed != 1 || s.Failed != 1 || s.NA != 1 {
		t.Errorf("score inesperado: %+v", s)
	}
	if ComputeScore(nil).Value != 100 {
		t.Error("sin controles evaluables la puntuación debe ser 100")
	}
}
