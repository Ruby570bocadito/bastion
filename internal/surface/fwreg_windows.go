//go:build windows

package surface

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Almacenes de reglas del Firewall de Windows en el registro que se aplican
// a la vez: el local, el de directivas de grupo y el de MDM (Intune).
const (
	fwLocalStore  = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`
	fwMDMStore    = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\FirewallRules`
	fwGPOStore    = `SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules`
	fwGPOProfiles = `SOFTWARE\Policies\Microsoft\WindowsFirewall\`
)

// readFirewallRules lee del registro las reglas de entrada activas. A
// diferencia de la interfaz COM, el registro trae siempre el paquete de las
// apps de la Store, los dispositivos de confianza (Wi-Fi Direct, UPnP…) y
// la exigencia de IPsec.
func readFirewallRules() ([]FirewallRule, error) {
	local, err := readRuleStore(fwLocalStore)
	if err != nil {
		return nil, err
	}
	// Una directiva de grupo puede impedir que las reglas locales se
	// apliquen en un perfil (AllowLocalPolicyMerge = 0).
	mask := 7
	for bit, name := range map[int]string{1: "DomainProfile", 2: "PrivateProfile", 4: "PublicProfile"} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, fwGPOProfiles+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		if v, _, err := k.GetIntegerValue("AllowLocalPolicyMerge"); err == nil && v == 0 {
			mask &^= bit
		}
		k.Close()
	}
	var rules []FirewallRule
	for _, r := range local {
		if r.Profiles &= mask; r.Profiles != 0 {
			rules = append(rules, r)
		}
	}
	for _, store := range []string{fwGPOStore, fwMDMStore} {
		extra, _ := readRuleStore(store) // solo existen con directivas o Intune
		rules = append(rules, extra...)
	}

	names := map[string]string{}
	var ifNames map[string]string
	for i := range rules {
		r := &rules[i]
		r.Name = indirectName(names, r.Name)
		if r.Interfaces == "" {
			continue
		}
		if ifNames == nil {
			ifNames = interfaceNames()
		}
		var out []string
		for _, id := range strings.Split(r.Interfaces, ",") {
			if n, ok := ifNames[strings.ToLower(id)]; ok {
				id = n
			}
			out = append(out, id)
		}
		r.Interfaces = strings.Join(out, ", ")
	}
	return rules, nil
}

func readRuleStore(path string) ([]FirewallRule, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadValueNames(0)
	if err != nil {
		return nil, err
	}
	var out []FirewallRule
	for _, n := range names {
		v, _, err := k.GetStringValue(n)
		if err != nil {
			continue
		}
		if r, ok := parseRegRule(v); ok {
			out = append(out, r)
		}
	}
	return out, nil
}

var procSHLoadIndirectString = windows.NewLazySystemDLL("shlwapi.dll").NewProc("SHLoadIndirectString")

// indirectName traduce los nombres que son recursos de una DLL
// ("@FirewallAPI.dll,-28502") al idioma del sistema. Los de apps de la
// Store ("@{…}") se dejan: esas reglas no se muestran y cargarlos es lento.
func indirectName(cache map[string]string, s string) string {
	if !strings.HasPrefix(s, "@") || strings.HasPrefix(s, "@{") {
		return s
	}
	if v, ok := cache[s]; ok {
		return v
	}
	v := s
	if src, err := windows.UTF16PtrFromString(s); err == nil && procSHLoadIndirectString.Find() == nil {
		buf := make([]uint16, 1024)
		hr, _, _ := procSHLoadIndirectString.Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
		if hr == 0 {
			if out := windows.UTF16ToString(buf); out != "" {
				v = out
			}
		}
	}
	cache[s] = v
	return v
}

// interfaceNames devuelve el nombre de cada adaptador de red por su GUID,
// que es como lo guardan las reglas limitadas a una interfaz.
func interfaceNames() map[string]string {
	out := map[string]string{}
	size := uint32(16 << 10)
	for range 3 {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_UNICAST|windows.GAA_FLAG_SKIP_ANYCAST|
			windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return out
		}
		for a := aa; a != nil; a = a.Next {
			out[strings.ToLower(windows.BytePtrToString(a.AdapterName))] = windows.UTF16PtrToString(a.FriendlyName)
		}
		return out
	}
	return out
}
