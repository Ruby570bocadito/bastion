//go:build windows

package surface

import (
	"bytes"
	"context"
	"os/exec"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/probes"
)

// Collect recoge el inventario en Windows con comandos fijos del sistema
// (netstat, tasklist) y consultas PowerShell de la lista blanca.
func Collect(ctx context.Context) (Inventory, error) {
	var inv Inventory
	out, err := run(ctx, probes.System32("netstat.exe"), "-ano")
	if err != nil {
		return inv, err
	}
	inv.Listeners = parseNetstat(out)
	if tl, err := run(ctx, probes.System32("tasklist.exe"), "/svc", "/fo", "csv", "/nh"); err == nil {
		procs := parseTasklist(tl)
		for i := range inv.Listeners {
			if p, ok := procs[inv.Listeners[i].PID]; ok {
				inv.Listeners[i].Process = p.image
				inv.Listeners[i].Services = p.services
			}
		}
	} else {
		inv.Notes = append(inv.Notes, "No se pudo asociar cada puerto con su proceso (tasklist): "+err.Error())
	}

	if data, err := probes.QueryPS(ctx, "smb_shares"); err == nil {
		inv.Shares = parsePSShares(data)
	} else if reason, ok := probes.AsPrivilege(err); ok {
		inv.Notes = append(inv.Notes, "Recursos compartidos sin evaluar: "+reason)
	} else {
		inv.Notes = append(inv.Notes, "No se pudieron leer los recursos compartidos: "+err.Error())
	}
	if data, err := probes.QueryPS(ctx, "local_admins"); err == nil {
		inv.Admins = parsePSAdmins(data)
	} else {
		inv.Notes = append(inv.Notes, "No se pudieron leer los miembros de Administradores: "+err.Error())
	}
	if !probes.Privileged() {
		inv.Notes = append(inv.Notes, "Sin privilegios de administrador algunos procesos aparecen sin nombre.")
	}
	return inv, nil
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}
