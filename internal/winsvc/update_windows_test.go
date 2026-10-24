package winsvc

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maks-ard/vpn-client/internal/app"
	"github.com/maks-ard/vpn-client/internal/update"
)

func TestSameSingBox(t *testing.T) {
	own := []byte("встроенный sing-box")
	dir := t.TempDir()
	same := filepath.Join(dir, "same.exe")
	other := filepath.Join(dir, "other.exe")
	_ = os.WriteFile(same, append(append([]byte("заголовок"), own...), "хвост"...), 0o600)
	_ = os.WriteFile(other, []byte("заголовок другой sing-box хвост"), 0o600)
	if !sameSingBox(same, own) {
		t.Error("тот же sing-box не найден")
	}
	if sameSingBox(other, own) || sameSingBox(filepath.Join(dir, "missing.exe"), own) || sameSingBox(same, nil) {
		t.Error("обновление с другим sing-box принято за бесшовное")
	}
}

func TestPendingUpdateIdleGrace(t *testing.T) {
	root := t.TempDir()
	m, err := app.NewManager(app.Paths{Config: filepath.Join(root, "config"), Data: filepath.Join(root, "data"), Logs: filepath.Join(root, "logs")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	h := &handler{pending: &pendingUpdate{release: &update.Release{Version: "v0.3.1"}, path: filepath.Join(root, "missing.exe")}}
	h.applyPending(m)
	if h.pending == nil || h.pending.idleSince.IsZero() {
		t.Fatal("не установлена пауза простоя")
	}
	h.applyPending(m)
	if h.pending == nil {
		t.Fatal("установка запущена до завершения паузы")
	}
	h.pending.idleSince = time.Now().Add(-6 * time.Second)
	h.applyPending(m)
	if h.pending != nil {
		t.Fatal("ошибка вызывает бесконечные автоматические повторы")
	}
	if h.info().Update == "" {
		t.Fatal("ошибка установки не показана")
	}
}
