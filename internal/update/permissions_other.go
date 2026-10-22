//go:build !windows

package update

import "os"

func prepareExecutable(path string) error { return os.Chmod(path, 0o755) }
