package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDNSQueryResult(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		ok         bool
	}{
		{"успех", `{"Status":0}`, true},
		{"несуществующее имя", `{"Status":3}`, true},
		{"сбой сервера", `{"Status":2}`, false},
		{"отказ", `{"Status":5}`, false},
		{"пустой ответ", `{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := &clash{base: srv.URL, http: srv.Client()}
			if err := c.dnsQuery(context.Background(), "test.example"); (err == nil) != tc.ok {
				t.Fatalf("dnsQuery: %v", err)
			}
		})
	}
}
