//go:build !windows

package app

import "os/exec"

func SetAutostart(enabled bool, exe string) error { return nil }

func OpenFile(path string) error { return exec.Command("xdg-open", path).Start() }
