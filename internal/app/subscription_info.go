package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/maks-ard/vpn-client/internal/subscription"
)

type subscriptionMetadata struct {
	Key     string            `json:"key"`
	Info    subscription.Info `json:"info"`
	Updated time.Time         `json:"updated"`
}

func subscriptionKey(link string) string {
	sum := sha256.Sum256([]byte(link))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) metadataFile() string { return filepath.Join(m.paths.Data, "subscription-info.json") }

func (m *Manager) loadSubscriptionInfo() {
	data, err := os.ReadFile(m.metadataFile())
	if err != nil {
		return
	}
	var cached subscriptionMetadata
	if json.Unmarshal(data, &cached) != nil || cached.Key != subscriptionKey(m.settings.Link) {
		return
	}
	applySubscriptionInfo(&m.state.Proxy, cached.Info, cached.Updated)
	m.state.Proxy.Outdated = true
}

func applySubscriptionInfo(p *ProxyState, info subscription.Info, updated time.Time) {
	p.Title, p.Used, p.Total = info.Title, info.Upload+info.Download, info.Total
	p.Expire, p.Updated = info.Expire, updated
}

// RefreshSubscription обновляет только сведения о подписке, не меняя туннель.
func (m *Manager) RefreshSubscription(ctx context.Context) {
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	link := m.Settings().Link
	if !strings.HasPrefix(link, "https://") && !strings.HasPrefix(link, "http://") {
		return
	}
	info, err := subscription.FetchInfo(ctx, link)
	if ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	if m.settings.Link != link {
		m.mu.Unlock()
		return
	}
	m.state = cloneState(m.state)
	if err != nil {
		m.state.Proxy.MetadataError = true
		m.state.Proxy.Outdated = !m.state.Proxy.Updated.IsZero()
	} else {
		updated := time.Now()
		applySubscriptionInfo(&m.state.Proxy, info, updated)
		m.state.Proxy.Outdated, m.state.Proxy.MetadataError = false, false
		// Только метаданные и отпечаток ссылки; сама ссылка не сохраняется.
		if data, marshalErr := json.Marshal(subscriptionMetadata{subscriptionKey(link), info, updated}); marshalErr == nil {
			if os.MkdirAll(m.paths.Data, 0o700) == nil {
				tmp := m.metadataFile() + ".tmp"
				if os.WriteFile(tmp, data, 0o600) == nil {
					_ = os.Rename(tmp, m.metadataFile())
				}
			}
		}
	}
	state := m.state
	m.mu.Unlock()
	m.notify(state)
}
