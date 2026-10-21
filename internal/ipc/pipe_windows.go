package ipc

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

const pipeName = `\\.\pipe\vpn-client`

// Доступ к каналу: система и администраторы — полный, пользователи,
// вошедшие в систему интерактивно, — чтение и запись (управление VPN из окна).
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// Listen открывает канал на стороне службы.
func Listen() (net.Listener, error) {
	return winio.ListenPipe(pipeName, &winio.PipeConfig{SecurityDescriptor: pipeSDDL})
}

// Dial подключается к службе.
func Dial(ctx context.Context) (net.Conn, error) {
	return winio.DialPipeContext(ctx, pipeName)
}
