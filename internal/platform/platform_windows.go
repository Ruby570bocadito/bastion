//go:build windows

package platform

import (
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func detect(info *Info) {
	info.Family = "windows"
	info.IsAdmin = windows.GetCurrentProcessToken().IsElevated()

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		name, _, _ := k.GetStringValue("ProductName")
		display, _, _ := k.GetStringValue("DisplayVersion")
		build, _, _ := k.GetStringValue("CurrentBuild")
		ubr, _, _ := k.GetIntegerValue("UBR")
		installType, _, _ := k.GetStringValue("InstallationType")
		k.Close()
		// En Windows 11 el registro sigue diciendo "Windows 10".
		if n, _ := strconv.Atoi(build); n >= 22000 && strings.HasPrefix(name, "Windows 10") {
			name = "Windows 11" + strings.TrimPrefix(name, "Windows 10")
		}
		if installType == "Server Core" {
			name += " (Server Core)"
		}
		info.Name = name
		info.Version = display
		info.Build = build + "." + strconv.FormatUint(ubr, 10)
	}

	productType := ""
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\ProductOptions`, registry.QUERY_VALUE); err == nil {
		productType, _, _ = k.GetStringValue("ProductType")
		k.Close()
	}
	switch productType {
	case "LanmanNT":
		info.Role = "dc"
		info.Tags = []string{"windows-dc", "windows-server", "windows"}
	case "ServerNT":
		info.Role = "server"
		info.Tags = []string{"windows-member", "windows-server", "windows"}
	default:
		info.Role = "workstation"
		info.Tags = []string{"windows-client", "windows"}
	}

	var buf *uint16
	var status uint32
	if err := windows.NetGetJoinInformation(nil, &buf, &status); err == nil {
		if status == windows.NetSetupDomainName {
			info.DomainJoined = true
			info.Domain = windows.UTF16PtrToString(buf)
		}
		windows.NetApiBufferFree((*byte)(unsafe.Pointer(buf)))
	}
}
