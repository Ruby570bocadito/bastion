//go:build !windows

package cli

import "errors"

func relaunchElevated([]string) error {
	return errors.New("la elevación automática solo existe en Windows: usa sudo")
}

func canElevate() bool { return false }
