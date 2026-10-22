package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubscriptionMetadataWithoutVPN(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "expire=1893456000; total=1000")
		fmt.Fprint(w, "test response")
	}))
	defer srv.Close()
	paths := testPaths(t)
	m, _ := NewManager(paths, nil)
	t.Cleanup(func() { _ = m.Close() })
	m.settings.Link = srv.URL
	m.RefreshSubscription(context.Background())
	if m.State().Proxy.Expire.Year() != 2030 || m.Active() {
		t.Fatal("метаданные не загружены без VPN")
	}
	restored, _ := NewManager(paths, nil)
	t.Cleanup(func() { _ = restored.Close() })
	restored.settings.Link = srv.URL
	restored.loadSubscriptionInfo()
	if restored.State().Proxy.Expire.Year() != 2030 {
		t.Fatal("кэш не восстановлен")
	}
	restored.state.Proxy.Expire = m.state.Proxy.Updated
	restored.settings.Link = srv.URL + "/other"
	before := restored.State().Proxy.Expire
	restored.loadSubscriptionInfo()
	if restored.State().Proxy.Expire != before {
		t.Fatal("метаданные другой ссылки применены")
	}
}
