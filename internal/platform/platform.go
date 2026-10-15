// Package platform detecta el sistema operativo, su rol y las etiquetas de
// plataforma con las que se seleccionan las reglas aplicables.
package platform

import (
	"os"
	"runtime"
	"strings"
)

// Info describe el equipo auditado.
type Info struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Family       string `json:"family"`
	Distro       string `json:"distro,omitempty"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Build        string `json:"build,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	Arch         string `json:"arch"`
	Role         string `json:"role"`
	DomainJoined bool   `json:"domain_joined"`
	Domain       string `json:"domain,omitempty"`
	EntraJoined  bool   `json:"entra_joined,omitempty"`
	Container    bool   `json:"container,omitempty"`
	IsAdmin      bool   `json:"is_admin"`
	// Tags va de la etiqueta más específica a la más general.
	Tags []string `json:"tags"`
}

// DisplayName devuelve el nombre del sistema con su versión sin repetirla.
func (i Info) DisplayName() string {
	if i.Version == "" || strings.Contains(i.Name, i.Version) {
		return i.Name
	}
	return i.Name + " " + i.Version
}

// Detect obtiene la información del equipo actual.
func Detect() Info {
	info := Info{OS: runtime.GOOS, Arch: runtime.GOARCH}
	info.Hostname, _ = os.Hostname()
	detect(&info)
	return info
}

// ParseOSRelease interpreta /etc/os-release.
func ParseOSRelease(text string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		m[k] = strings.Trim(v, `"'`)
	}
	return m
}

// linuxTags calcula las etiquetas a partir de ID e ID_LIKE de os-release.
func linuxTags(id, idLike string) []string {
	var tags []string
	add := func(t string) {
		for _, x := range tags {
			if x == t {
				return
			}
		}
		tags = append(tags, t)
	}
	norm := func(s string) string {
		switch s {
		case "rocky", "almalinux", "centos", "ol", "rhel":
			return "rhel"
		case "opensuse", "opensuse-leap", "sles", "suse":
			return "suse"
		}
		return s
	}
	if id != "" {
		add("linux-" + id)
		add("linux-" + norm(id))
	}
	for _, l := range strings.Fields(idLike) {
		add("linux-" + norm(l))
	}
	add("linux")
	return tags
}
