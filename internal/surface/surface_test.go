package surface

import (
	"sort"
	"strings"
	"testing"
	"time"

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
			{Name: "Público", Bit: 4, Enabled: true, BlockInbound: true},
		},
		Rules: []FirewallRule{
			{Name: "Escritorio remoto - Modo de usuario (TCP de entrada)", Allow: true, Protocol: 6, LocalPorts: "3389",
				App: `%SystemRoot%\system32\svchost.exe`, Service: "termservice", Profiles: 0x7fffffff, Remote: "*"},
			{Name: "Compartir archivos e impresoras (SMB de entrada)", Allow: true, Protocol: 6, LocalPorts: "445", App: "System", Profiles: 4, Remote: "LocalSubnet"},
			{Name: "Steam", Allow: true, Protocol: 256, App: `C:\Program Files (x86)\Steam\steam.exe`, Profiles: 2, Remote: "*"},
			{Name: "Bloquear Steam UDP", Allow: false, Protocol: 17, LocalPorts: "27036", Profiles: 2},
			{Name: "RPC dinámico", Allow: true, Protocol: 6, LocalPorts: "RPC", Service: "*", Profiles: 2},
			{Name: "Rango", Allow: true, Protocol: 17, LocalPorts: "47998-48010", Profiles: 2},
		},
	}
	cases := []struct {
		p    Port
		open bool
		why  string
	}{
		{Port{Proto: "tcp", Port: 3389, Process: "svchost.exe", Services: []string{"TermService"}}, true, "Escritorio remoto"},
		{Port{Proto: "tcp", Port: 3389, Process: "otro.exe"}, false, "ninguna regla"},
		{Port{Proto: "tcp", Port: 445, Process: "System"}, false, "perfil Privado"}, // la regla solo es del perfil Público
		{Port{Proto: "tcp", Port: 27036, Process: "steam.exe"}, true, "Steam"},
		{Port{Proto: "udp", Port: 27036, Process: "steam.exe"}, false, "regla de bloqueo"},
		{Port{Proto: "tcp", Port: 49666, Process: "svchost.exe", Services: []string{"Schedule"}}, true, "RPC dinámico"},
		{Port{Proto: "tcp", Port: 49665, Process: "wininit.exe"}, false, ""}, // sin servicio: no casa con Service "*"
		{Port{Proto: "udp", Port: 48000, Process: "sunshine.exe"}, true, "Rango"},
		{Port{Proto: "tcp", Port: 48000, Process: "sunshine.exe"}, false, ""},
	}
	for _, c := range cases {
		open, why := fw.Evaluate(c.p)
		if open != c.open || !strings.Contains(why, c.why) {
			t.Errorf("%d/%s %s → %v %q, quiero %v (%q)", c.p.Port, c.p.Proto, c.p.Process, open, why, c.open, c.why)
		}
	}
	// Una regla limitada a direcciones remotas lo dice; un perfil desactivado lo abre todo.
	fw.Profiles[2].Active, fw.Profiles[1].Active = true, false
	if open, why := fw.Evaluate(Port{Proto: "tcp", Port: 445, Process: "System"}); !open || !strings.Contains(why, "solo desde LocalSubnet") {
		t.Errorf("SMB en red pública: %v %q", open, why)
	}
	fw.Profiles[2].Enabled = false
	if open, why := fw.Evaluate(Port{Proto: "tcp", Port: 9999}); !open || !strings.Contains(why, "desactivado") {
		t.Errorf("firewall desactivado: %v %q", open, why)
	}

	// Con el firewall evaluado, lo filtrado no genera hallazgos ni resta.
	inv := Inventory{Firewall: fw, Listeners: []Listener{
		{Proto: "tcp", Address: "0.0.0.0", Port: 3389, Scope: ScopeNetwork, Process: "svchost.exe", Services: []string{"TermService"}},
	}}
	fw.Profiles[2].Enabled = true
	fw.Rules[0].Allow = false // ahora es una regla de bloqueo
	rep := Analyze(inv, platform.Info{}, "test", time.Now())
	if len(rep.Findings) != 0 || rep.Reachable != 0 || rep.Exposed != 1 || rep.Ports[0].Firewall != "filtered" {
		t.Errorf("RDP filtrado: %+v %+v", rep.Findings, rep.Ports)
	}
}

func TestParsePSFirewall(t *testing.T) {
	data := map[string]any{
		"profiles": []any{
			map[string]any{"Bit": 1.0, "Enabled": true, "BlockInbound": true, "Active": false},
			map[string]any{"Bit": 2.0, "Enabled": true, "BlockInbound": true, "Active": true},
		},
		"rules": map[string]any{"N": "Escritorio remoto", "A": 1.0, "P": 6.0, "L": "3389", "App": "", "S": "", "Pr": 2147483647.0, "R": "*"},
	}
	fw := parsePSFirewall(data)
	if fw == nil || len(fw.Profiles) != 2 || fw.Profiles[1].Name != "Privado" || !fw.Profiles[1].Active || fw.InboundRules != 1 || !fw.Rules[0].Allow {
		t.Errorf("firewall: %+v", fw)
	}
	if parsePSFirewall(map[string]any{}) != nil {
		t.Error("sin perfiles no hay evaluación")
	}
}
