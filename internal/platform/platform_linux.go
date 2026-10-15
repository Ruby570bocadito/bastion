//go:build linux

package platform

import (
	"os"
	"strings"
)

func detect(info *Info) {
	info.Family = "linux"
	info.IsAdmin = os.Geteuid() == 0
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		m := ParseOSRelease(string(b))
		info.Distro = m["ID"]
		info.Name = m["PRETTY_NAME"]
		info.Version = m["VERSION_ID"]
		info.Tags = linuxTags(m["ID"], m["ID_LIKE"])
	} else {
		info.Name = "Linux"
		info.Tags = []string{"linux"}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(b))
	}
	info.Container = isContainer()
	info.Role = "server"
	if isGraphical() {
		info.Role = "workstation"
	}
}

func isContainer() bool {
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		return strings.Contains(s, "docker") || strings.Contains(s, "kubepods") || strings.Contains(s, "containerd")
	}
	return false
}

// isGraphical considera estación de trabajo un equipo cuyo destino por
// defecto de systemd es graphical.target.
func isGraphical() bool {
	target, err := os.Readlink("/etc/systemd/system/default.target")
	return err == nil && strings.Contains(target, "graphical")
}
