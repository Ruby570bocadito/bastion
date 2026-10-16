package remediate

import "testing"

func TestDescribeFwRemote(t *testing.T) {
	cases := []struct {
		before State
		want   string
	}{
		{State{"display": "hydra-python-rpc.exe", "remote": "Any", "proto": "UDP", "ports": "Any"},
			"regla «hydra-python-rpc.exe» (UDP): direcciones remotas Any → LocalSubnet"},
		{State{"display": "Steam Web Helper", "remote": "Any", "proto": "UDP", "ports": "5353"},
			"regla «Steam Web Helper» (UDP 5353): direcciones remotas Any → LocalSubnet"},
		{State{"display": "Sunshine", "remote": "Any", "proto": "TCP", "ports": "47984,47989,47990"},
			"regla «Sunshine» (TCP 47984, 47989, 47990): direcciones remotas Any → LocalSubnet"},
		{State{"display": "Total War", "remote": "Any", "proto": "Any", "ports": "Any"},
			"regla «Total War»: direcciones remotas Any → LocalSubnet"},
		// Instantáneas de versiones anteriores, sin protocolo.
		{State{"display": "AutoClaw Desktop App", "remote": "Any"},
			"regla «AutoClaw Desktop App»: direcciones remotas Any → LocalSubnet"},
		{State{"remote": "Any"}, "regla «{CFB7}»: direcciones remotas Any → LocalSubnet"},
	}
	for _, c := range cases {
		if got := describeFwRemote("{CFB7}", "LocalSubnet", c.before); got != c.want {
			t.Errorf("\n  %s\nquiero\n  %s", got, c.want)
		}
	}
}
