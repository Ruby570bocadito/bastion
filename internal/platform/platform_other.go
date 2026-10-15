//go:build !linux && !windows

package platform

func detect(info *Info) {
	info.Family = info.OS
	info.Name = info.OS
	info.Role = "unknown"
	info.Tags = []string{info.OS}
}
