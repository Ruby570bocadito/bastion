//go:build linux

package surface

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Collect recoge el inventario en Linux leyendo /proc y /etc (sin ejecutar
// comandos).
func Collect(_ context.Context) (Inventory, error) {
	var inv Inventory
	var socks []procSocket
	for _, src := range []struct {
		file, proto string
		v6          bool
	}{{"tcp", "tcp", false}, {"tcp6", "tcp", true}, {"udp", "udp", false}, {"udp6", "udp", true}} {
		b, err := os.ReadFile("/proc/net/" + src.file)
		if err != nil {
			continue // sin IPv6, p. ej.
		}
		socks = append(socks, parseProcNet(string(b), src.proto, src.v6)...)
	}
	lo, hi := ephemeralRange()
	owners, complete := socketOwners()
	if !complete {
		inv.Notes = append(inv.Notes, "Sin root no se ven los procesos de otros usuarios: ejecuta con sudo para saber qué proceso abre cada puerto.")
	}
	for _, s := range socks {
		l := s.Listener
		l.Ephemeral = l.Proto == "udp" && l.Port >= lo && l.Port <= hi
		if pid, ok := owners[s.inode]; ok {
			l.PID = pid
			l.Process = processName(pid)
		}
		inv.Listeners = append(inv.Listeners, l)
	}

	if b, err := os.ReadFile("/etc/exports"); err == nil {
		inv.Shares = append(inv.Shares, parseExports(string(b))...)
	}
	extra, _ := filepath.Glob("/etc/exports.d/*.exports")
	for _, f := range extra {
		if b, err := os.ReadFile(f); err == nil {
			inv.Shares = append(inv.Shares, parseExports(string(b))...)
		}
	}
	if b, err := os.ReadFile("/etc/samba/smb.conf"); err == nil {
		inv.Shares = append(inv.Shares, parseSmbConf(string(b))...)
	}

	passwd, err1 := os.ReadFile("/etc/passwd")
	group, err2 := os.ReadFile("/etc/group")
	if err1 == nil && err2 == nil {
		inv.Admins = parseLinuxAdmins(string(passwd), string(group))
	}
	return inv, nil
}

// socketOwners asocia el inodo de cada socket con el PID que lo tiene
// abierto. complete es false si algún proceso no se pudo inspeccionar.
func socketOwners() (map[string]int, bool) {
	owners := map[string]int{}
	complete := true
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return owners, false
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", p.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				complete = false
			}
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, ok := owners[inode]; !ok {
				owners[inode] = pid
			}
		}
	}
	return owners, complete
}

// ephemeralRange es el rango de puertos locales que el kernel asigna a los
// clientes (net.ipv4.ip_local_port_range; por defecto 32768-60999).
func ephemeralRange() (int, int) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err == nil {
		if f := strings.Fields(string(b)); len(f) == 2 {
			lo, err1 := strconv.Atoi(f[0])
			hi, err2 := strconv.Atoi(f[1])
			if err1 == nil && err2 == nil && lo > 0 && hi >= lo {
				return lo, hi
			}
		}
	}
	return 32768, 60999
}

func processName(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
