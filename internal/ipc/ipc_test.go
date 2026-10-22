package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maks-ard/vpn-client/internal/app"
)

func startServer(t *testing.T) (*Client, *app.Manager) {
	t.Helper()
	dir := t.TempDir()
	srv := NewServer(func() Info { return Info{Version: "v1.2.3"} }, nil, nil)
	m, err := app.NewManager(app.Paths{Config: filepath.Join(dir, "c"), Data: filepath.Join(dir, "d")}, srv.Broadcast)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetManager(m)
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go Serve(l, srv.Handler())
	t.Cleanup(func() { l.Close() })
	c := NewClient(func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	})
	return c, m
}

func TestClientServer(t *testing.T) {
	c, m := startServer(t)
	ctx := context.Background()

	info, err := c.Info(ctx)
	if err != nil || info.Version != "v1.2.3" {
		t.Fatalf("info: %+v %v", info, err)
	}

	states := make(chan app.State, 10)
	evCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.Events(evCtx, func(s app.State) { states <- s })
	if st := <-states; st.Status != app.StatusDisconnected {
		t.Fatalf("первое состояние: %+v", st)
	}

	// Ошибка валидации доходит до окна текстом.
	err = c.SaveSettings(ctx, app.Settings{Link: "ftp://bad"})
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("ожидалась ошибка валидации, получено %v", err)
	}
	if err := c.SaveSettings(ctx, app.Settings{Link: "https://sub.example.com/x", RussiaDirect: true}); err != nil {
		t.Fatal(err)
	}
	select {
	case st := <-states:
		if !st.Proxy.Enabled {
			t.Errorf("после сохранения подписка не видна в состоянии: %+v", st.Proxy)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("нет события после сохранения настроек")
	}
	view, err := c.Settings(ctx)
	if err != nil || view.Settings.Link != "https://sub.example.com/x" || m.Settings().Link != view.Settings.Link {
		t.Fatalf("settings: %+v %v", view, err)
	}

	ovpnData, _ := os.ReadFile("../singbox/testdata/corp.ovpn")
	ovpnInfo, err := c.ImportOVPN(ctx, "work.ovpn", ovpnData)
	if err != nil || !ovpnInfo.Loaded || ovpnInfo.Name != "work.ovpn" || !ovpnInfo.NeedsAuth {
		t.Fatalf("import: %+v %v", ovpnInfo, err)
	}
	if _, err := c.ImportOVPN(ctx, "bad.ovpn", []byte("garbage")); err == nil {
		t.Error("ожидалась ошибка для неверного .ovpn")
	}
	if err := c.RemoveOVPN(ctx); err != nil {
		t.Fatal(err)
	}

	log, err := c.Log(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = log
}

func TestClientUnavailable(t *testing.T) {
	c := NewClient(func(ctx context.Context) (net.Conn, error) {
		return nil, errors.New("нет канала")
	})
	if _, err := c.Info(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ожидалась ErrUnavailable, получено %v", err)
	}
}

func TestInstallUpdateError(t *testing.T) {
	c, _ := startServer(t)
	// Без установщика ошибка доходит до окна, а не теряется.
	if err := c.InstallUpdate(context.Background()); err == nil || !strings.Contains(err.Error(), "недоступна") {
		t.Fatalf("ожидалась ошибка установки, получено %v", err)
	}
}
