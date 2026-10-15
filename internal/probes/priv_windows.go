//go:build windows

package probes

import "golang.org/x/sys/windows"

func isPrivileged() bool { return windows.GetCurrentProcessToken().IsElevated() }
