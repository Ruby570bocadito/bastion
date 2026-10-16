package remediate

import (
	"fmt"
	"strings"
)

// describeFwRemote describe el cambio de firewall.remote_address. Muestra el
// protocolo y los puertos de la regla para distinguir las que se llaman
// igual (Windows crea una para TCP y otra para UDP al aceptar el aviso del
// firewall de un programa).
func describeFwRemote(rule, remote string, before State) string {
	name := textOf(before["display"])
	if name == "—" || name == "" {
		name = rule
	}
	if w := fwProtoPorts(textOf(before["proto"]), textOf(before["ports"])); w != "" {
		name = "«" + name + "» (" + w + ")"
	} else {
		name = "«" + name + "»"
	}
	return fmt.Sprintf("regla %s: direcciones remotas %s → %s", name, textOf(before["remote"]), remote)
}

// fwProtoPorts resume protocolo y puertos locales: "UDP 5353", "TCP" (todos
// los puertos) o "" (cualquier protocolo).
func fwProtoPorts(proto, ports string) string {
	proto = strings.TrimSpace(proto)
	if proto == "" || proto == "—" || strings.EqualFold(proto, "Any") {
		return ""
	}
	proto = strings.ToUpper(proto)
	ports = strings.TrimSpace(ports)
	if ports == "" || ports == "—" || strings.EqualFold(ports, "Any") {
		return proto
	}
	if len(ports) > 40 {
		ports = ports[:40] + "…"
	}
	return proto + " " + strings.ReplaceAll(ports, ",", ", ")
}
