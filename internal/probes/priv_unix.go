//go:build !windows

package probes

import "os"

func isPrivileged() bool { return os.Geteuid() == 0 }
