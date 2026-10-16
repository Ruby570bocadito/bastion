package surface

import (
	"bufio"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Los parsers no dependen del sistema: se prueban en cualquier plataforma.

// procSocket es una línea de /proc/net/{tcp,udp}[6].
type procSocket struct {
	Listener
	inode string
}

// parseProcNet interpreta /proc/net/tcp|udp (v6 = tcp6|udp6). Devuelve los
// sockets TCP en LISTEN (0A) y los UDP sin conectar (07 con remoto vacío).
func parseProcNet(content, proto string, v6 bool) []procSocket {
	var out []procSocket
	sc := bufio.NewScanner(strings.NewReader(content))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		local, remote, st, inode := f[1], f[2], f[3], f[9]
		switch proto {
		case "tcp":
			if st != "0A" {
				continue
			}
		case "udp":
			if st != "07" || !strings.HasSuffix(remote, ":0000") {
				continue
			}
		}
		addr, port, err := decodeProcAddr(local, v6)
		if err != nil || port == 0 {
			continue
		}
		out = append(out, procSocket{Listener: Listener{Proto: proto, Address: addr, Port: port, Scope: ScopeOf(addr)}, inode: inode})
	}
	return out
}

// decodeProcAddr convierte "0100007F:0016" en ("127.0.0.1", 22). Las
// direcciones van en el orden de bytes del equipo, palabra a palabra de
// 32 bits (little-endian en x86 y ARM).
func decodeProcAddr(s string, v6 bool) (string, int, error) {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, fmt.Errorf("dirección inválida %q", s)
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return "", 0, err
	}
	raw, err := hex.DecodeString(hexIP)
	if err != nil || (len(raw) != 4 && len(raw) != 16) || (v6 && len(raw) != 16) {
		return "", 0, fmt.Errorf("dirección inválida %q", s)
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	if v4 := ip.To4(); v4 != nil && len(raw) == 16 && !ip.Equal(net.IPv6zero) {
		return v4.String(), int(port), nil // ::ffff:a.b.c.d
	}
	if ip.Equal(net.IPv6zero) {
		return "::", int(port), nil
	}
	return ip.String(), int(port), nil
}

// parseNetstat interpreta "netstat -ano" de Windows. Las cabeceras y el
// estado dependen del idioma, así que un socket TCP se reconoce como "a la
// escucha" porque su dirección remota es 0.0.0.0:0 o [::]:0.
func parseNetstat(out string) []Listener {
	var ls []Listener
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		proto := strings.ToLower(f[0])
		var local, pidStr string
		switch {
		case proto == "tcp" && len(f) == 5:
			if f[2] != "0.0.0.0:0" && f[2] != "[::]:0" {
				continue
			}
			local, pidStr = f[1], f[4]
		case proto == "udp" && len(f) == 4:
			if f[2] != "*:*" {
				continue
			}
			local, pidStr = f[1], f[3]
		default:
			continue
		}
		host, portStr, err := net.SplitHostPort(local)
		if err != nil {
			continue
		}
		port, err1 := strconv.Atoi(portStr)
		pid, err2 := strconv.Atoi(pidStr)
		if err1 != nil || err2 != nil || port == 0 {
			continue
		}
		ls = append(ls, Listener{Proto: proto, Address: host, Port: port, Scope: ScopeOf(host), PID: pid})
	}
	return ls
}

// procInfo es un proceso de Windows con sus servicios.
type procInfo struct {
	image    string
	services []string
}

// parseTasklist interpreta "tasklist /svc /fo csv /nh": imagen, PID y
// servicios. "N/A" (o su traducción, p. ej. "N/D") significa ninguno.
func parseTasklist(out string) map[int]procInfo {
	m := map[int]procInfo{}
	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1
	records, _ := r.ReadAll()
	for _, rec := range records {
		if len(rec) < 3 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(rec[1]))
		if err != nil {
			continue
		}
		p := procInfo{image: strings.TrimSpace(rec[0])}
		svc := strings.TrimSpace(rec[2])
		if svc != "" && !strings.Contains(svc, "/") {
			for _, s := range strings.Split(svc, ",") {
				if s = strings.TrimSpace(s); s != "" {
					p.services = append(p.services, s)
				}
			}
		}
		m[pid] = p
	}
	return m
}

// parseTasklistUsers interpreta "tasklist /v /fo csv /nh": devuelve el
// usuario de cada PID (séptima columna). "N/A" o su traducción, vacío.
func parseTasklistUsers(out string) map[int]string {
	m := map[int]string{}
	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1
	records, _ := r.ReadAll()
	for _, rec := range records {
		if len(rec) < 7 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(rec[1]))
		user := strings.TrimSpace(rec[6])
		if err != nil || user == "" || strings.Contains(user, "/") {
			continue
		}
		m[pid] = user
	}
	return m
}

// parseExports interpreta /etc/exports: "ruta cliente(opciones) cliente…".
func parseExports(content string) []Share {
	var out []Share
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		f := strings.Fields(line)
		if len(f) == 0 || !strings.HasPrefix(f[0], "/") {
			continue
		}
		s := Share{Kind: "nfs", Name: f[0], Path: f[0]}
		opts := map[string]bool{}
		for _, client := range f[1:] {
			host, o, _ := strings.Cut(client, "(")
			if host == "" || host == "*" {
				opts["*"] = true
			}
			s.Access = append(s.Access, ShareAccess{Account: firstNonEmpty(host, "*"), Right: nfsRight(o)})
			for _, opt := range strings.Split(strings.TrimSuffix(o, ")"), ",") {
				if opt == "no_root_squash" {
					opts[opt] = true
				}
			}
		}
		for _, k := range []string{"no_root_squash", "*"} {
			if opts[k] {
				s.Options = append(s.Options, k)
			}
		}
		out = append(out, s)
	}
	return out
}

func nfsRight(opts string) string {
	for _, o := range strings.Split(strings.TrimSuffix(opts, ")"), ",") {
		if o == "rw" {
			return "Change"
		}
	}
	return "Read"
}

// parseSmbConf interpreta smb.conf: recursos con guest ok y escritura.
func parseSmbConf(content string) []Share {
	var out []Share
	var cur *Share
	flush := func() {
		if cur != nil && cur.Name != "global" {
			out = append(out, *cur)
		}
	}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			cur = &Share{Kind: "samba", Name: strings.ToLower(strings.Trim(line, "[]"))}
			if cur.Name == "printers" || cur.Name == "print$" {
				cur = &Share{Kind: "samba", Name: "global"} // impresoras: se ignoran
			}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.Join(strings.Fields(strings.ToLower(k)), " ")
		v = strings.ToLower(strings.TrimSpace(v))
		yes := v == "yes" || v == "true" || v == "1"
		no := v == "no" || v == "false" || v == "0"
		switch k {
		case "path":
			cur.Path = strings.TrimSpace(line[strings.IndexByte(line, '=')+1:])
		case "guest ok", "public":
			if yes {
				cur.Options = appendOnce(cur.Options, "guest ok")
			}
		case "writable", "writeable", "write ok":
			if yes {
				cur.Options = appendOnce(cur.Options, "writable")
			}
		case "read only":
			if no {
				cur.Options = appendOnce(cur.Options, "writable")
			}
		}
	}
	flush()
	return out
}

// parseLinuxAdmins devuelve las cuentas con UID 0 y los miembros de los
// grupos de administración (sudo, wheel, admin) a partir de /etc/passwd y
// /etc/group (legibles sin root).
func parseLinuxAdmins(passwd, group string) []Account {
	var out []Account
	gidOf := map[string]string{}
	primary := map[string][]string{} // gid → usuarios con ese grupo primario
	sc := bufio.NewScanner(strings.NewReader(passwd))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 7 {
			continue
		}
		if f[2] == "0" {
			out = append(out, Account{Name: f[0], Kind: "usuario", Source: "UID 0"})
		}
		primary[f[3]] = append(primary[f[3]], f[0])
	}
	seen := map[string]bool{}
	sc = bufio.NewScanner(strings.NewReader(group))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 4 {
			continue
		}
		name := f[0]
		gidOf[name] = f[2]
		if name != "sudo" && name != "wheel" && name != "admin" {
			continue
		}
		members := strings.Split(f[3], ",")
		members = append(members, primary[f[2]]...)
		for _, m := range members {
			m = strings.TrimSpace(m)
			if m == "" || seen[name+"|"+m] {
				continue
			}
			seen[name+"|"+m] = true
			out = append(out, Account{Name: m, Kind: "usuario", Source: "grupo " + name})
		}
	}
	return out
}

// parsePSShares interpreta la consulta PowerShell "smb_shares".
func parsePSShares(data map[string]any) []Share {
	var out []Share
	for _, it := range asList(data["shares"]) {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		s := Share{Kind: "smb", Name: str(m["Name"]), Path: str(m["Path"])}
		for _, a := range asList(m["Access"]) {
			am, ok := a.(map[string]any)
			if !ok {
				continue
			}
			s.Access = append(s.Access, ShareAccess{Account: str(am["Account"]), SID: str(am["SID"]),
				Right: str(am["Right"]), Deny: strings.EqualFold(str(am["Type"]), "Deny")})
		}
		out = append(out, s)
	}
	return out
}

// parsePSAdmins interpreta la consulta PowerShell "local_admins".
func parsePSAdmins(data map[string]any) []Account {
	var out []Account
	for _, it := range asList(data["members"]) {
		switch v := it.(type) {
		case map[string]any:
			out = append(out, Account{Name: str(v["Name"]), Kind: str(v["Type"]), Source: str(v["Source"])})
		case string:
			out = append(out, Account{Name: v})
		}
	}
	return out
}

// PowerShell serializa una lista de un elemento como el elemento suelto.
func asList(v any) []any {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		return x
	default:
		return []any{x}
	}
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func appendOnce(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// parsePSFirewall interpreta la consulta PowerShell "firewall_policy"
// (HNetCfg.FwPolicy2: perfiles y reglas de entrada habilitadas).
func parsePSFirewall(data map[string]any) *Firewall {
	fw := &Firewall{}
	for _, it := range asList(data["profiles"]) {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		bit := int(num(m["Bit"]))
		fw.Profiles = append(fw.Profiles, FirewallProfile{Name: profileNames[bit], Bit: bit,
			Enabled: truthy(m["Enabled"]), BlockInbound: truthy(m["BlockInbound"]), Active: truthy(m["Active"])})
	}
	for _, it := range asList(data["rules"]) {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		fw.Rules = append(fw.Rules, FirewallRule{Name: str(m["N"]), Allow: num(m["A"]) == 1, Protocol: int(num(m["P"])),
			LocalPorts: str(m["L"]), App: str(m["App"]), Service: str(m["S"]), Profiles: int(num(m["Pr"])),
			Local: str(m["LA"]), Remote: str(m["R"]), Interfaces: str(m["I"]), IfTypes: str(m["IT"]),
			Package: str(m["Pk"]), UserOwner: str(m["U"])})
	}
	fw.InboundRules = len(fw.Rules)
	if len(fw.Profiles) == 0 {
		return nil
	}
	return fw
}

func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	}
	return 0
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	case float64:
		return x != 0
	}
	return false
}
