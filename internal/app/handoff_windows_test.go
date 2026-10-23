package app

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maks-ard/vpn-client/internal/singbox"
)

// TestHandoffWithSingBox: служба отдаёт работающий sing-box новой версии,
// и уже открытое через него соединение не рвётся.
func TestHandoffWithSingBox(t *testing.T) {
	exe := os.Getenv("VPNCLIENT_SINGBOX")
	if exe == "" {
		t.Skip("VPNCLIENT_SINGBOX не задан")
	}
	links := "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:9?security=tls&sni=a.example.com#NL\n"
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(links))))
	}))
	defer sub.Close()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c) }()
		}
	}()
	proxyAddr, err := freeLocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(proxyAddr)
	port, _ := strconv.Atoi(portText)

	paths := testPaths(t)
	newManager := func() *Manager {
		m, err := NewManager(paths, nil)
		if err != nil {
			t.Fatal(err)
		}
		m.singBoxPath = exe
		m.inbound = singbox.M{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port}
		return m
	}
	old := newManager()
	if err := old.SaveSettings(Settings{Link: sub.URL}); err != nil {
		t.Fatal(err)
	}
	old.Connect()
	waitStatus(t, old, StatusConnected)
	connectedAt := old.State().ConnectedAt

	conn := socks5(t, proxyAddr, echo.Addr().String())
	defer conn.Close()
	ping(t, conn)

	if _, err := old.HandOff(); err != nil {
		t.Fatal(err)
	}
	if old.Active() {
		t.Fatal("после передачи старый менеджер считает VPN своим")
	}
	old.Connect()
	if old.Active() {
		t.Fatal("после передачи старый менеджер запустил второй sing-box")
	}
	ping(t, conn)

	next := newManager()
	t.Cleanup(func() { next.Disconnect(); _ = next.log.Close() })
	adopted, err := next.Adopt()
	if !adopted || err != nil {
		t.Fatalf("подхват: %v, %v", adopted, err)
	}
	// Прежняя служба завершается, не останавливая sing-box.
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if st := next.State(); st.Status != StatusConnected || !st.ConnectedAt.Equal(connectedAt) {
		t.Fatalf("состояние после подхвата: %+v", st)
	}
	ping(t, conn)

	// Журнал подхваченного процесса приходит через Clash API.
	logCtx, stopLogs := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopLogs()
	lines := make(chan clashLog, 16)
	go func() {
		_ = next.api.logs(logCtx, "debug", func(l clashLog) {
			select {
			case lines <- l:
			default:
			}
		})
	}()
	time.Sleep(300 * time.Millisecond)
	socks5(t, proxyAddr, echo.Addr().String()).Close()
	select {
	case l := <-lines:
		if l.Type == "" || l.Payload == "" {
			t.Errorf("запись журнала без уровня или текста: %+v", l)
		}
	case <-logCtx.Done():
		t.Error("журнал sing-box не пришёл через Clash API")
	}

	if _, err := os.Stat(paths.handoffFile()); !os.IsNotExist(err) {
		t.Errorf("файл передачи не удалён: %v", err)
	}
	if ok, err := next.Adopt(); ok || err != nil {
		t.Errorf("повторный подхват: %v, %v", ok, err)
	}

	next.Disconnect()
	if st := next.State(); st.Status != StatusDisconnected {
		t.Fatalf("после отключения: %+v", st)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err == nil {
		if _, err := io.ReadFull(conn, make([]byte, 4)); err == nil {
			t.Error("соединение живо после отключения: sing-box не остановлен")
		}
	}
}

func waitStatus(t *testing.T, m *Manager, want Status) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for m.State().Status != want {
		if st := m.State(); st.Status == StatusError || time.Now().After(deadline) {
			t.Fatalf("ожидалось %s: %+v", want, st)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func socks5(t *testing.T, proxy, target string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	host, portText, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portText)
	ip := net.ParseIP(host).To4()
	req := []byte{5, 1, 0, 5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 12)
	if _, err := io.ReadFull(c, resp); err != nil || resp[0] != 5 || resp[3] != 0 {
		t.Fatalf("SOCKS5: %v %v", err, resp)
	}
	_ = c.SetDeadline(time.Time{})
	return c
}

func ping(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("соединение оборвалось: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || !strings.EqualFold(string(buf), "ping") {
		t.Fatalf("соединение оборвалось: %v %q", err, buf)
	}
}
