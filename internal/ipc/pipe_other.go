//go:build !windows

package ipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
)

// Вне Windows вместо named pipe — unix-сокет (для разработки и тестов).
var socketPath = filepath.Join(os.TempDir(), "vpn-client.sock")

func Listen() (net.Listener, error) {
	_ = os.Remove(socketPath)
	return net.Listen("unix", socketPath)
}

func Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", socketPath)
}
