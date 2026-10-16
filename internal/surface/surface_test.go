package surface

import (
	"sort"
	"strings"
	"testing"
	"time"

	"net"

	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:B663 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2147 2 00000000c473a531 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3001 1 00000000614dd911 100 0 0 10 0
   2: 0501A8C0:0016 6401A8C0:D431 01 00000000:00000000 02:000A7B2A 00000000     0        0 3002 4 0000000000000000 20 4 30 10 -1
`
	got := parseProcNet(tcp, "tcp", false)
	if len(got) != 2 {
		t.Fatalf("quiero 2 sockets en LISTEN, hay %d: %+v", len(got), got)
	}
	if got[0].Address != "127.0.0.1" || got[0].Port != 46691 || got[0].Scope != ScopeLoopback || got[0].inode != "2147" {
		t.Errorf("loopback: %+v", got[0])
	}
	if got[1].Address != "0.0.0.0" || got[1].Port != 22 || got[1].Scope != ScopeNetwork {
		t.Errorf("ssh: %+v", got[1])
	}

	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4001 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4002 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4003 1 0000000000000000 100 0 0 10 0
`
	got = parseProcNet(tcp6, "tcp", true)
	want := []struct {
		addr  string
		port  int
		scope string
	}{{"::", 80, ScopeNetwork}, {"::1", 631, ScopeLoopback}, {"127.0.0.1", 8080, ScopeLoopback}}
	if len(got) != len(want) {
		t.Fatalf("tcp6: %+v", got)
	}
	for i, w := range want {
		if got[i].Address != w.addr || got[i].Port != w.port || got[i].Scope != w.scope {
			t.Errorf("tcp6[%d] = %s:%d %s, quiero %s:%d %s", i, got[i].Address, got[i].Port, got[i].Scope, w.addr, w.port, w.scope)
		}
	}

	udp := `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 5001 2 0000000000000000 0
  101: 0501A8C0:A1B2 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 5002 2 0000000000000000 0
`
	got = parseProcNet(udp, "udp", false)
	if len(got) != 1 || got[0].Port != 68 || got[0].Proto != "udp" {
		t.Errorf("udp: %+v", got)
	}
}

func TestParseNetstatTasklist(t *testing.T) {
	// Salida de un Windows en español: cabeceras y estados traducidos.
	netstat := `
Conexiones activas

  Proto  Dirección local          Dirección remota        Estado           PID
  TCP    0.0.0.0:135            0.0.0.0:0              ESCUCHANDO       1012
  TCP    0.0.0.0:445            0.0.0.0:0              ESCUCHANDO       4
  TCP    127.0.0.1:5939         0.0.0.0:0              ESCUCHANDO       4567
  TCP    192.168.1.5:139        0.0.0.0:0              ESCUCHANDO       4
  TCP    192.168.1.5:50000      52.1.1.1:443           ESTABLECIDO      8888
  TCP    [::]:445               [::]:0                 ESCUCHANDO       4
  TCP    [::1]:49670            [::]:0                 ESCUCHANDO       3333
  UDP    0.0.0.0:5355           *:*                                    1500
  UDP    [fe80::1c2d:3e4f:5a6b:7c8d%12]:1900  *:*                       3000
  UDP    192.168.1.5:50001      52.1.1.1:3478                          9999
`
	ls := parseNetstat(netstat)
	if len(ls) != 8 {
		t.Fatalf("quiero 8 sockets a la escucha, hay %d: %+v", len(ls), ls)
	}
	byKey := map[string]Listener{}
	for _, l := range ls {
		byKey[l.Proto+" "+l.Address] = l
	}
	if l := byKey["tcp 127.0.0.1"]; l.Port != 5939 || l.Scope != ScopeLoopback || l.PID != 4567 {
		t.Errorf("loopback: %+v", l)
	}
	if l := byKey["udp fe80::1c2d:3e4f:5a6b:7c8d%12"]; l.Port != 1900 || l.Scope != ScopeNetwork {
		t.Errorf("IPv6 con zona: %+v", l)
	}

	tasklist := `"System Idle Process","0","N/D"
"System","4","N/D"
"svchost.exe","1012","RpcEptMapper,RpcSs"
"svchost.exe","1500","Dnscache"
"chrome.exe","4567","N/A"
`
	procs := parseTasklist(tasklist)
	if p := procs[1012]; p.image != "svchost.exe" || strings.Join(p.services, "|") != "RpcEptMapper|RpcSs" {
		t.Errorf("svchost: %+v", p)
	}
	if p := procs[4]; p.image != "System" || len(p.services) != 0 {
		t.Errorf("System: %+v", p)
	}
}

func TestParseShares(t *testing.T) {
	exports := `# /etc/exports
/srv/nfs/public   *(ro,sync)
/srv/nfs/home     10.0.0.0/24(rw,sync,no_root_squash) backup(ro)
`
	sh := parseExports(exports)
	if len(sh) != 2 || strings.Join(sh[0].Options, ",") != "*" || strings.Join(sh[1].Options, ",") != "no_root_squash" {
		t.Fatalf("exports: %+v", sh)
	}
	if sh[1].Access[0].Right != "Change" || sh[1].Access[1].Right != "Read" {
		t.Errorf("permisos NFS: %+v", sh[1].Access)
	}

	smb := `[global]
   workgroup = WORKGROUP
   guest ok = yes
[publico]
   path = /srv/publico
   guest ok = yes
   read only = no
[docs]
   path = /srv/docs
   public = yes
[privado]
   path = /srv/privado
   valid users = @equipo
[printers]
   guest ok = yes
`
	sh = parseSmbConf(smb)
	if len(sh) != 3 {
		t.Fatalf("smb.conf: %+v", sh)
	}
	if sh[0].Name != "publico" || strings.Join(sh[0].Options, ",") != "guest ok,writable" || sh[0].Path != "/srv/publico" {
		t.Errorf("[publico]: %+v", sh[0])
	}
	if strings.Join(sh[1].Options, ",") != "guest ok" || len(sh[2].Options) != 0 {
		t.Errorf("[docs] / [privado]: %+v %+v", sh[1], sh[2])
	}
}

func TestParseAdmins(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nana:x:1000:1000::/home/ana:/bin/bash\nluis:x:1001:27::/home/luis:/bin/bash\n"
	group := "root:x:0:\nsudo:x:27:ana\nusers:x:100:ana,luis\n"
	got := parseLinuxAdmins(passwd, group)
	var names []string
	for _, a := range got {
		names = append(names, a.Name+"("+a.Source+")")
	}
	if strings.Join(names, " ") != "root(UID 0) toor(UID 0) ana(grupo sudo) luis(grupo sudo)" {
		t.Errorf("administradores: %v", names)
	}

	ps := map[string]any{"members": []any{
		map[string]any{"Name": `PC\Administrador`, "Type": "Usuario", "Source": "Local"},
		map[string]any{"Name": `AzureAD\ana`, "Type": "Usuario", "Source": "AzureAD"},
	}}
	if a := parsePSAdmins(ps); len(a) != 2 || a[1].Source != "AzureAD" {
		t.Errorf("PS admins: %+v", a)
	}
	// PowerShell 5.1 serializa un único elemento sin corchetes; ADSI devuelve nombres sueltos.
	if a := parsePSAdmins(map[string]any{"members": "Administrador"}); len(a) != 1 || a[0].Name != "Administrador" {
		t.Errorf("PS admins (uno): %+v", a)
	}
	shares := parsePSShares(map[string]any{"shares": map[string]any{"Name": "Datos", "Path": `D:\Datos`,
		"Access": map[string]any{"Account": "Todos", "SID": "S-1-1-0", "Right": "Change", "Type": "Allow"}}})
	if len(shares) != 1 || len(shares[0].Access) != 1 || shares[0].Access[0].SID != "S-1-1-0" {
		t.Errorf("PS shares: %+v", shares)
	}
}

func TestAnalyze(t *testing.T) {
	inv := Inventory{
		Listeners: []Listener{
			{Proto: "tcp", Address: "0.0.0.0", Port: 3389, Scope: ScopeNetwork, Process: "svchost.exe", Services: []string{"TermService"}},
			{Proto: "tcp", Address: "::", Port: 3389, Scope: ScopeNetwork, Process: "svchost.exe"},
			{Proto: "tcp", Address: "0.0.0.0", Port: 22, Scope: ScopeNetwork, Process: "sshd"},
			{Proto: "tcp", Address: "127.0.0.1", Port: 6379, Scope: ScopeLoopback, Process: "redis-server"},
			{Proto: "tcp", Address: "0.0.0.0", Port: 8443, Scope: ScopeNetwork, Process: "app"},
			{Proto: "udp", Address: "0.0.0.0", Port: 445, Scope: ScopeNetwork},                 // SMB es TCP: no cuenta
			{Proto: "tcp", Address: "0.0.0.0", Port: 22, Scope: ScopeNetwork, Process: "sshd"}, // duplicado
		},
		Shares: []Share{
			{Kind: "smb", Name: "Datos", Path: `D:\Datos`, Access: []ShareAccess{{Account: "Todos", SID: "S-1-1-0", Right: "Change"}, {Account: "Admins", SID: "S-1-5-32-544", Right: "Full"}}},
			{Kind: "nfs", Path: "/srv", Options: []string{"no_root_squash"}},
		},
	}
	rep := Analyze(inv, platform.Info{Hostname: "pc"}, "test", time.Now())
	// Servicios en la red: 3389 (IPv4 e IPv6 del mismo proceso), 22, 8443 y 445/udp.
	if len(rep.Listeners) != 6 || rep.Exposed != 4 || rep.Reachable != 4 {
		t.Errorf("escuchas %d (quiero 6), expuestos %d (quiero 4), accesibles %d", len(rep.Listeners), rep.Exposed, rep.Reachable)
	}
	if p := rep.Ports[0]; p.Port != 22 || len(rep.Ports) != 5 {
		t.Errorf("puertos agrupados: %+v", rep.Ports)
	}
	for _, p := range rep.Ports {
		if p.Port == 3389 && (len(p.Addresses) != 2 || p.Firewall != "") {
			t.Errorf("RDP agrupado (sin firewall evaluado): %+v", p)
		}
	}
	var ids []string
	var rdp Finding
	for _, f := range rep.Findings {
		ids = append(ids, string(f.Severity)+":"+f.ID)
		if f.ID == "SURF-PORT-3389" {
			rdp = f
		}
	}
	sort.Strings(ids)
	// RDP una sola vez (IPv4 e IPv6), SSH es informativo, Redis en loopback no cuenta.
	if strings.Join(ids, " ") != "high:SURF-PORT-3389 high:SURF-SHARE-NFS-ROOT high:SURF-SHARE-SMB" {
		t.Errorf("hallazgos: %v", ids)
	}
	if rep.Score != 55 || rep.Grade != "F" { // 100 - 3×15
		t.Errorf("puntuación %d %s, quiero 55 F", rep.Score, rep.Grade)
	}
	if rep.Ports[0].Known != "SSH" {
		t.Error("los puertos conocidos deben llevar el nombre del servicio")
	}
	if !strings.Contains(rdp.Title, "svchost.exe · TermService") {
		t.Errorf("el hallazgo debe decir qué proceso y servicio escuchan: %s", rdp.Title)
	}
	clean := Analyze(Inventory{}, platform.Info{}, "test", time.Now())
	if clean.Score != 100 || clean.Findings == nil || clean.Listeners == nil {
		t.Errorf("sin nada expuesto: %+v", clean)
	}
	if rep.Findings[0].Severity != rule.SevHigh {
		t.Errorf("los hallazgos se ordenan por severidad: %+v", rep.Findings[0])
	}
}

func TestNetBIOSAndEphemeral(t *testing.T) {
	inv := Inventory{Listeners: []Listener{
		{Proto: "udp", Address: "192.168.1.5", Port: 137, Scope: ScopeNetwork, PID: 4, Process: "System"},
		{Proto: "udp", Address: "192.168.1.5", Port: 138, Scope: ScopeNetwork, PID: 4, Process: "System"},
		{Proto: "tcp", Address: "192.168.1.5", Port: 139, Scope: ScopeNetwork, PID: 4, Process: "System"},
		{Proto: "udp", Address: "0.0.0.0", Port: 52706, Scope: ScopeNetwork, PID: 3132, Process: "svchost.exe", Ephemeral: true},
		{Proto: "tcp", Address: "0.0.0.0", Port: 49664, Scope: ScopeNetwork, PID: 1492, Process: "lsass.exe"},
	}}
	rep := Analyze(inv, platform.Info{}, "test", time.Now())
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "SURF-NETBIOS" || rep.Findings[0].Subject != "137/udp, 138/udp, 139/tcp" {
		t.Fatalf("NetBIOS debe ser un único hallazgo: %+v", rep.Findings)
	}
	if rep.Score != 93 {
		t.Errorf("puntuación %d, quiero 93 (un hallazgo medio)", rep.Score)
	}
	// El socket UDP efímero del cliente DNS no es un servicio expuesto.
	if rep.Exposed != 4 {
		t.Errorf("expuestos %d, quiero 4", rep.Exposed)
	}
	for _, p := range rep.Ports {
		if p.Port == 49664 && p.Known != "RPC dinámico (Windows)" {
			t.Errorf("RPC dinámico sin etiquetar: %+v", p)
		}
	}
}

func TestFirewallEvaluate(t *testing.T) {
	fw := &Firewall{
		Profiles: []FirewallProfile{
			{Name: "Dominio", Bit: 1, Enabled: true, BlockInbound: true},
			{Name: "Privado", Bit: 2, Enabled: true, BlockInbound: true, Active: true},
			{Name: "Público", Bit: 4, Enabled: true, BlockInbound: true, Active: true},
		},
		Rules: []FirewallRule{
			// Como la crea Tailscale: cualquier puerto, pero solo hacia las IP de Tailscale.
			{Name: "Tailscale-In", Allow: true, Protocol: 256, Profiles: 3, Local: "100.127.45.81,fd7a:115c:a1e0::bf01:2dbf", Remote: "*"},
			{Name: "OpenSSH SSH Server (sshd)", Allow: true, Protocol: 6, LocalPorts: "22", Profiles: 0x7fffffff, Local: "*", Remote: "*"},
			{Name: "Compartir archivos e impresoras (SMB de entrada)", Allow: true, Protocol: 6, LocalPorts: "445", App: "System", Profiles: 2, Remote: "LocalSubnet"},
			{Name: "Detección de redes (SSDP de entrada)", Allow: true, Protocol: 17, LocalPorts: "1900", Service: "SSDPSRV", Profiles: 2, Remote: "LocalSubnet"},
			{Name: "Steam", Allow: true, Protocol: 256, App: `C:\Program Files (x86)\Steam\steam.exe`, Profiles: 2, Remote: "*"},
			{Name: "Bloquear Steam UDP", Allow: false, Protocol: 17, LocalPorts: "27036", Profiles: 6},
			{Name: "Sunshine (cable)", Allow: true, Protocol: 6, LocalPorts: "47984-48010", Profiles: 6, IfTypes: "Lan"},
			{Name: "Admin desde 10.0.0.0/8", Allow: true, Protocol: 6, LocalPorts: "5985", Profiles: 2, Remote: "10.0.0.0/255.0.0.0"},
		},
	}
	all := []string{"0.0.0.0", "::"}
	cases := []struct {
		name  string
		p     Port
		state string
		limit string
	}{
		{"RDP solo por Tailscale", Port{Proto: "tcp", Port: 3389, Addresses: all, Process: "svchost.exe", Services: []string{"TermService"}}, FirewallLimited, "Tailscale"},
		{"SSH abierto (una regla sin límites gana)", Port{Proto: "tcp", Port: 22, Addresses: all, Process: "sshd.exe"}, FirewallOpen, ""},
		{"SMB: Tailscale y red local", Port{Proto: "tcp", Port: 445, Addresses: all, Process: "System"}, FirewallLimited, "Tailscale y la red local"},
		{"NetBIOS en la IP de la LAN: Tailscale-In no lo cubre", Port{Proto: "udp", Port: 137, Addresses: []string{"192.168.1.131"}, Process: "System"}, FirewallFiltered, ""},
		{"tailscaled en su IP", Port{Proto: "tcp", Port: 52722, Addresses: []string{"100.127.45.81"}, Process: "tailscaled.exe"}, FirewallLimited, "Tailscale"},
		{"Steam TCP abierto", Port{Proto: "tcp", Port: 27036, Addresses: []string{"0.0.0.0"}, Process: "steam.exe"}, FirewallOpen, ""},
		{"Steam UDP bloqueado", Port{Proto: "udp", Port: 27036, Addresses: []string{"0.0.0.0"}, Process: "steam.exe"}, FirewallFiltered, ""},
		{"Sunshine por cable y por Tailscale", Port{Proto: "tcp", Port: 47989, Addresses: []string{"0.0.0.0"}, Process: "sunshine.exe"}, FirewallLimited, "Tailscale y en red cableada"},
		{"WinRM solo desde una subred", Port{Proto: "tcp", Port: 5985, Addresses: []string{"0.0.0.0"}, Process: "System"}, FirewallLimited, "Tailscale y desde 10.0.0.0/255.0.0.0"},
	}
	for _, c := range cases {
		a := fw.Evaluate(c.p)
		if a.State != c.state || a.Limit != c.limit {
			t.Errorf("%s: %s %q (%s), quiero %s %q", c.name, a.State, a.Limit, a.Why, c.state, c.limit)
		}
	}
	if a := fw.Evaluate(cases[0].p); !strings.Contains(a.Why, "Tailscale-In") || !strings.HasPrefix(a.Why, "solo desde Tailscale") {
		t.Errorf("la explicación debe nombrar la regla: %q", a.Why)
	}
	if a := fw.Evaluate(cases[1].p); !strings.Contains(a.Why, "OpenSSH") {
		t.Errorf("SSH: %q", a.Why)
	}
	// Un perfil desactivado lo abre todo.
	fw.Profiles[2].Enabled = false
	if a := fw.Evaluate(Port{Proto: "tcp", Port: 9999, Addresses: all}); a.State != FirewallOpen || !strings.Contains(a.Why, "desactivado") {
		t.Errorf("firewall desactivado: %+v", a)
	}
	fw.Profiles[2].Enabled = true

	// En el análisis: lo filtrado no cuenta, lo limitado baja un nivel.
	inv := Inventory{Firewall: fw, Listeners: []Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 3389, Scope: ScopeNetwork, Process: "svchost.exe", Services: []string{"TermService"}},
		{Proto: "tcp", Address: "::", Port: 3389, Scope: ScopeNetwork, Process: "svchost.exe", Services: []string{"TermService"}},
		{Proto: "udp", Address: "192.168.1.131", Port: 137, Scope: ScopeNetwork, PID: 4, Process: "System"},
		{Proto: "udp", Address: "0.0.0.0", Port: 5353, Scope: ScopeNetwork, Process: "chrome.exe"},
	}}
	rep := Analyze(inv, platform.Info{}, "test", time.Now())
	if rep.Exposed != 3 || rep.Reachable != 2 || rep.Limited != 2 {
		t.Errorf("expuestos %d (3), accesibles %d (2), limitados %d (2)", rep.Exposed, rep.Reachable, rep.Limited)
	}
	// RDP alto → medio por estar limitado a Tailscale; mDNS bajo → informativo (sin hallazgo); NetBIOS filtrado.
	if len(rep.Findings) != 1 || rep.Findings[0].Severity != rule.SevMedium || !strings.Contains(rep.Findings[0].Title, "solo desde Tailscale") {
		t.Fatalf("hallazgos: %+v", rep.Findings)
	}
	if rep.Score != 93 {
		t.Errorf("puntuación %d, quiero 93", rep.Score)
	}
}

func TestStoreAppAndAllowAllRules(t *testing.T) {
	profiles := []FirewallProfile{
		{Name: "Dominio", Bit: 1, Enabled: true, BlockInbound: true},
		{Name: "Privado", Bit: 2, Enabled: true, BlockInbound: true, Active: true},
		{Name: "Público", Bit: 4, Enabled: true, BlockInbound: true, Active: true},
	}
	rdp := Port{Proto: "tcp", Port: 3389, Addresses: []string{"0.0.0.0"}, Process: "svchost.exe", Services: []string{"TermService"}}
	chrome := Port{Proto: "udp", Port: 5353, Addresses: []string{"0.0.0.0"}, Process: "chrome.exe"}

	// Regla de una app de la Store: sin programa, pero solo para su AppContainer.
	fw := &Firewall{Profiles: profiles, Rules: []FirewallRule{
		{Name: "XBOX", Allow: true, Protocol: 256, Profiles: 2, Package: "S-1-15-2-1234-5678"},
		{Name: "Regla de usuario", Allow: true, Protocol: 17, LocalPorts: "5353", Profiles: 2, UserOwner: "S-1-5-21-1-2-3-1001"},
	}}
	if a := fw.Evaluate(rdp); a.State != FirewallFiltered {
		t.Errorf("una regla de app de la Store no abre RDP: %+v", a)
	}
	if a := fw.Evaluate(Port{Proto: "udp", Port: 5353, Addresses: []string{"0.0.0.0"}, Process: "svchost.exe", Services: []string{"Dnscache"}}); a.State != FirewallFiltered {
		t.Errorf("una regla de usuario no cubre un servicio del sistema: %+v", a)
	}
	if a := fw.Evaluate(chrome); a.State != FirewallOpen {
		t.Errorf("una regla de usuario sí cubre sus programas: %+v", a)
	}
	if n := len(fw.AllowAll()); n != 0 {
		t.Errorf("las reglas de apps no cuentan como «permitir todo»: %d", n)
	}

	// Una regla de verdad sin límites: lo abre todo y es un hallazgo por sí misma.
	fw.Rules = append(fw.Rules, FirewallRule{Name: "Todo abierto", Allow: true, Protocol: 256, LocalPorts: "*", Profiles: 2, Local: "*", Remote: "*"})
	if a := fw.Evaluate(rdp); a.State != FirewallOpen || !strings.Contains(a.Why, "Todo abierto") {
		t.Errorf("con una regla sin límites RDP queda abierto: %+v", a)
	}
	rep := Analyze(Inventory{Firewall: fw}, platform.Info{}, "test", time.Now())
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "SURF-FW-ALLOWALL" || rep.Findings[0].Severity != rule.SevHigh ||
		!strings.Contains(rep.Findings[0].Fix, "Disable-NetFirewallRule") || !strings.Contains(rep.Findings[0].Title, "Privado") {
		t.Errorf("hallazgo de regla «permitir todo»: %+v", rep.Findings)
	}
	// En un perfil que no está activo no es un hallazgo.
	fw.Rules[2].Profiles = 1
	if n := len(fw.AllowAll()); n != 0 {
		t.Errorf("perfil Dominio inactivo: %d", n)
	}
}

func TestUserOwnedRules(t *testing.T) {
	const rafag = "S-1-5-21-1236394060-1900707475-1329702642-1001"
	fw := &Firewall{
		Profiles: []FirewallProfile{
			{Name: "Dominio", Bit: 1, Enabled: true, BlockInbound: true},
			{Name: "Privado", Bit: 2, Enabled: true, BlockInbound: true, Active: true},
			{Name: "Público", Bit: 4, Enabled: true, BlockInbound: true, Active: true},
		},
		// Las reglas reales del equipo de la prueba: sin programa ni paquete, pero de un usuario.
		Rules: []FirewallRule{
			{Name: "XBOX", Allow: true, Protocol: 256, Profiles: 3, Local: "*", Remote: "*", UserOwner: rafag},
			{Name: "Xbox", Allow: true, Protocol: 256, Profiles: 3, Local: "*", Remote: "*", UserOwner: rafag},
		},
	}
	all := []string{"0.0.0.0", "::"}
	cases := []struct {
		name  string
		p     Port
		state string
	}{
		{"RDP (servicio del sistema)", Port{Proto: "tcp", Port: 3389, Addresses: all, Process: "svchost.exe", Services: []string{"TermService"}, UserSID: "S-1-5-20"}, FirewallFiltered},
		{"SMB (System)", Port{Proto: "tcp", Port: 445, Addresses: all, Process: "System", UserSID: "S-1-5-18"}, FirewallFiltered},
		{"NinjaTrader del usuario", Port{Proto: "tcp", Port: 4530, Addresses: all, Process: "NinjaTrader.exe", UserSID: rafag}, FirewallOpen},
		{"programa de otro usuario", Port{Proto: "tcp", Port: 8080, Addresses: all, Process: "app.exe", UserSID: "S-1-5-21-9-9-9-1002"}, FirewallFiltered},
		{"tailscaled (servicio, sin usuario conocido)", Port{Proto: "udp", Port: 41641, Addresses: all, Process: "tailscaled.exe", Services: []string{"Tailscale"}}, FirewallFiltered},
		{"programa sin usuario conocido", Port{Proto: "tcp", Port: 8766, Addresses: all, Process: "AutoClaw.exe"}, FirewallOpen},
	}
	for _, c := range cases {
		if a := fw.Evaluate(c.p); a.State != c.state {
			t.Errorf("%s: %s (%s), quiero %s", c.name, a.State, a.Why, c.state)
		}
	}
	rep := Analyze(Inventory{Firewall: fw}, platform.Info{}, "test", time.Now())
	if len(rep.Findings) != 1 {
		t.Fatalf("hallazgos: %+v", rep.Findings)
	}
	f := rep.Findings[0]
	if f.ID != "SURF-FW-USERALLOWALL" || f.Severity != rule.SevMedium || !strings.Contains(f.Title, "«XBOX» y «Xbox» permiten") ||
		!strings.Contains(f.Title, "Dominio y Privado") || !strings.Contains(f.Fix, "-DisplayName 'XBOX' -Direction Inbound") {
		t.Errorf("hallazgo de reglas de usuario: %+v", f)
	}
	if !strings.Contains(f.Fix, "'XBOX'") || strings.Contains(f.Fix, "'Xbox'") {
		t.Errorf("los nombres que solo cambian en mayúsculas se listan una vez: %s", f.Fix)
	}
}

func TestParseTasklistUsers(t *testing.T) {
	out := `"svchost.exe","1760","Services","0","12.345 KB","Unknown","NT AUTHORITY\NETWORK SERVICE","0:00:01","N/D"
"NinjaTrader.exe","14132","Console","1","512.000 KB","Running","RBY\rafag","0:10:00","NinjaTrader"
"System","4","Services","0","152 KB","Unknown","N/D","0:20:00","N/D"
`
	u := parseTasklistUsers(out)
	if u[1760] != `NT AUTHORITY\NETWORK SERVICE` || u[14132] != `RBY\rafag` {
		t.Errorf("usuarios: %v", u)
	}
	if _, ok := u[4]; ok {
		t.Error("N/D no es un usuario")
	}
}

func TestParseAddrs(t *testing.T) {
	set := parseAddrs("100.127.45.81/255.255.255.255,fd7a:115c:a1e0::/48,10.0.0.1-10.0.0.9")
	for ip, want := range map[string]bool{"100.127.45.81": true, "100.127.45.82": false, "fd7a:115c:a1e0::1": true, "10.0.0.5": true, "10.0.0.10": false} {
		if got := set.contains(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %v, quiero %v", ip, got, want)
		}
	}
	if d := parseAddrs("100.127.45.81,fd7a:115c:a1e0::bf01:2dbf").describe(true); d != "Tailscale" {
		t.Errorf("describe Tailscale: %q", d)
	}
	if d := parseAddrs("LocalSubnet").describe(false); d != "la red local" {
		t.Errorf("describe LocalSubnet: %q", d)
	}
	if !parseAddrs("LocalSubnet").contains(net.ParseIP("1.2.3.4")) {
		t.Error("una palabra clave se asume que contiene la dirección")
	}
}

func TestParsePSFirewall(t *testing.T) {
	data := map[string]any{
		"profiles": []any{
			map[string]any{"Bit": 1.0, "Enabled": true, "BlockInbound": true, "Active": false},
			map[string]any{"Bit": 2.0, "Enabled": true, "BlockInbound": true, "Active": true},
		},
		"rules": map[string]any{"N": "Tailscale-In", "A": 1.0, "P": 256.0, "L": "*", "App": "", "S": "", "Pr": 3.0, "LA": "100.127.45.81", "R": "*", "I": "", "IT": "All"},
	}
	fw := parsePSFirewall(data)
	if fw == nil || len(fw.Profiles) != 2 || fw.Profiles[1].Name != "Privado" || !fw.Profiles[1].Active || fw.InboundRules != 1 || !fw.Rules[0].Allow || fw.Rules[0].Local != "100.127.45.81" {
		t.Errorf("firewall: %+v", fw)
	}
	if parsePSFirewall(map[string]any{}) != nil {
		t.Error("sin perfiles no hay evaluación")
	}
}

func TestParseRegRule(t *testing.T) {
	const rafag = "S-1-5-21-1236394060-1900707475-1329702642-1001"
	// Cadenas como las que guarda Windows 11 en
	// HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules.
	raw := []string{
		`v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-28502|Desc=@FirewallAPI.dll,-28503|EmbedCtxt=@FirewallAPI.dll,-28502|`,
		`v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|App=System|Name=Solo controlador de WFD (TCP de entrada)|EmbedCtxt=@wfdprov.dll,-100|TTK=WFDKmDriver|`,
		`v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|Profile=Public|LPort=1900|App=%SystemRoot%\system32\svchost.exe|Svc=Ssdpsrv|Name=Detección de red de Teredo (SSDP de entrada)|Edge=TRUE|TTK=UPnP|`,
		`v2.33|Action=Allow|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Name=XBOX|LUOwn=` + rafag + `|AppPkgId=S-1-15-2-1430448594-2639229838-973813799-439329657-1197984847-4069523365-1300003023|EmbedCtxt=XBOX|Platform=2:6:2|Platform2=GTEQ|`,
		`v2.33|Action=Allow|Active=TRUE|Dir=In|Profile=Private|Name=@{Microsoft.WindowsStore_22409.1401.5.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsStore/Resources/StoreTitle}|PFN=Microsoft.WindowsStore_8wekyb3d8bbwe|`,
		`v2.33|Action=Allow|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|LA4=100.127.45.81|LA6=fd7a:115c:a1e0::bf01:2dbf|Name=Tailscale-In|`,
		`v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=3389|App=%SystemRoot%\system32\svchost.exe|Svc=termservice|Name=Escritorio remoto - Modo usuario (TCP de entrada)|`,
		`v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5986|Name=WinRM con IPsec|Security=AuthenticateEncrypt|`,
		`v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=22|Name=Desactivada|`,
		`v2.33|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=443|Name=Salida|`,
		`v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=5355|Name=Bloquear LLMNR|`,
		`v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=RPC|LPort2_10=IPTLSIn|LPort2_10=IPHTTPSIn|App=System|Name=Puertos con palabras clave|`,
		`no es una regla`,
	}
	var rules []FirewallRule
	for _, s := range raw {
		if r, ok := parseRegRule(s); ok {
			rules = append(rules, r)
		}
	}
	if len(rules) != 10 {
		t.Fatalf("reglas de entrada activas: %d, quiero 10", len(rules))
	}
	smb, wfd, xbox, store, ts, rdp := rules[0], rules[1], rules[3], rules[4], rules[5], rules[6]
	if smb.Protocol != 6 || smb.Profiles != 2 || smb.LocalPorts != "445" || smb.Remote != "LocalSubnet,LocalSubnet" || smb.App != "System" || !smb.Allow {
		t.Errorf("SMB: %+v", smb)
	}
	if wfd.Profiles != 7 || wfd.Trust != "WFDKmDriver" {
		t.Errorf("WFD: sin Profile son todos y TTK es un límite: %+v", wfd)
	}
	if xbox.Protocol != 256 || xbox.Profiles != 3 || xbox.UserOwner != rafag || xbox.Package == "" || !xbox.storeApp() {
		t.Errorf("XBOX es de una app de la Store: %+v", xbox)
	}
	if store.Package != "Microsoft.WindowsStore_8wekyb3d8bbwe" || !store.storeApp() {
		t.Errorf("con PFN también es de la Store: %+v", store)
	}
	if ts.Local != "100.127.45.81,fd7a:115c:a1e0::bf01:2dbf" || ts.Remote != "" {
		t.Errorf("Tailscale-In: %+v", ts)
	}
	if rdp.Service != "termservice" || rdp.Profiles != 6 {
		t.Errorf("RDP: %+v", rdp)
	}
	if !rules[7].Secure || rules[8].Allow || rules[9].LocalPorts != "RPC,IPTLSIn,IPHTTPSIn" {
		t.Errorf("IPsec, bloqueo o palabras clave de puertos: %+v %+v %+v", rules[7], rules[8], rules[9])
	}

	// La evaluación con estas reglas: lo que en el equipo de la prueba salía
	// «abierto a cualquiera» por WFD, Teredo y XBOX queda limitado o filtrado.
	fw := &Firewall{Source: "registry", Rules: rules, Profiles: []FirewallProfile{
		{Name: "Dominio", Bit: 1, Enabled: true, BlockInbound: true},
		{Name: "Privado", Bit: 2, Enabled: true, BlockInbound: true, Active: true},
		{Name: "Público", Bit: 4, Enabled: true, BlockInbound: true, Active: true},
	}}
	all := []string{"0.0.0.0", "::"}
	cases := []struct {
		name  string
		p     Port
		state string
		limit string
	}{
		{"SMB", Port{Proto: "tcp", Port: 445, Addresses: all, Process: "System"}, FirewallLimited, "la red local, Wi-Fi Direct y Tailscale"},
		{"SSDP", Port{Proto: "udp", Port: 1900, Addresses: all, Process: "svchost.exe", Services: []string{"SSDPSRV"}}, FirewallLimited, "Tailscale y dispositivos UPnP"},
		{"programa del usuario: XBOX no lo cubre, solo Tailscale-In", Port{Proto: "tcp", Port: 4530, Addresses: []string{"0.0.0.0"}, Process: "NinjaTrader.exe", UserSID: rafag}, FirewallLimited, "Tailscale"},
		{"en la IP de la LAN no llega nada", Port{Proto: "tcp", Port: 4530, Addresses: []string{"192.168.1.131"}, Process: "NinjaTrader.exe", UserSID: rafag}, FirewallFiltered, ""},
		{"RDP", Port{Proto: "tcp", Port: 3389, Addresses: all, Process: "svchost.exe", Services: []string{"TermService"}}, FirewallOpen, ""},
		{"WinRM con IPsec", Port{Proto: "tcp", Port: 5986, Addresses: []string{"192.168.1.131"}, Process: "System"}, FirewallLimited, "con IPsec"},
		{"LLMNR bloqueado", Port{Proto: "udp", Port: 5355, Addresses: []string{"192.168.1.131"}, Process: "svchost.exe", Services: []string{"Dnscache"}}, FirewallFiltered, ""},
		{"IP-HTTPS", Port{Proto: "tcp", Port: 443, Addresses: []string{"192.168.1.131"}, Process: "System"}, FirewallOpen, ""},
	}
	for _, c := range cases {
		a := fw.Evaluate(c.p)
		if a.State != c.state || a.Limit != c.limit {
			t.Errorf("%s: %s %q (%s), quiero %s %q", c.name, a.State, a.Limit, a.Why, c.state, c.limit)
		}
	}
	if a := fw.Evaluate(cases[5].p); a.Why != "solo con IPsec (regla «WinRM con IPsec»)" {
		t.Errorf("explicación con IPsec: %q", a.Why)
	}
	if n := len(fw.AllowAll()) + len(fw.UserAllowAll()); n != 0 {
		t.Errorf("ninguna de estas reglas lo permite todo: %d", n)
	}
	// Una regla de bloqueo limitada a dispositivos de confianza no bloquea todo.
	fw.Rules = append(fw.Rules, FirewallRule{Name: "Bloqueo WFD", Protocol: 6, LocalPorts: "3389", Profiles: 7, Trust: "WFDKmDriver"})
	if a := fw.Evaluate(cases[4].p); a.State != FirewallOpen {
		t.Errorf("RDP con un bloqueo parcial: %+v", a)
	}
}

func TestDescribeKeywords(t *testing.T) {
	for in, want := range map[string]string{
		"LocalSubnet,LocalSubnet":    "la red local",
		"LocalSubnet,DNS":            "la red local y los servidores DNS",
		"IntrAnet,10.0.0.0/8":        "la intranet y desde 10.0.0.0/8",
		"Ply2Renders":                "dispositivos de «Reproducir en»",
		"192.168.1.0/24,192.168.2.1": "desde 192.168.1.0/24, 192.168.2.1",
		"Desconocida":                "desde Desconocida",
	} {
		if got := parseAddrs(in).describe(false); got != want {
			t.Errorf("%s: %q, quiero %q", in, got, want)
		}
	}
	if got := trustLabel("WFDPrint,WFDDisplay,ProxApp,Otra"); got != "Wi-Fi Direct, dispositivos cercanos y dispositivos de confianza (Otra)" {
		t.Errorf("trustLabel: %q", got)
	}
}

func TestLabelsAndShortLists(t *testing.T) {
	for _, c := range []struct {
		proto string
		port  int
		want  string
	}{{"tcp", 5357, "WSD (detección de dispositivos)"}, {"udp", 47998, "Sunshine/GameStream"}, {"udp", 41641, "Tailscale (WireGuard)"}, {"tcp", 41641, ""}} {
		if got := label(c.proto, c.port); got != c.want {
			t.Errorf("%s/%d: %q, quiero %q", c.proto, c.port, got, c.want)
		}
	}
	if got := shortList([]string{"«A»", "«B»", "«C»", "«D»", "«E»"}, 3); got != "«A», «B», «C» y 2 más" {
		t.Errorf("shortList: %q", got)
	}
	if got := shortList([]string{"«A»", "«B»"}, 3); got != "«A» y «B»" {
		t.Errorf("shortList corta: %q", got)
	}
	inv := Inventory{Listeners: []Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 7680, Scope: ScopeNetwork, Process: "svchost.exe", Services: []string{"DoSvc"}},
	}}
	rep := Analyze(inv, platform.Info{}, "test", time.Now())
	if len(rep.Findings) != 0 || rep.Ports[0].Known != "Optimización de distribución (Windows Update)" {
		t.Errorf("un puerto etiquetado no es un hallazgo: %+v %+v", rep.Ports, rep.Findings)
	}
}
