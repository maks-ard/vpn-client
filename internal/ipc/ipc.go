// Package ipc — связь окна (обычные права) со службой (права системы):
// HTTP поверх named pipe \\.\pipe\vpn-client. Служба держит app.Manager,
// окно вызывает его методы и получает поток состояний.
package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/maks-ard/vpn-client/internal/app"
)

// Info — версия службы: окно сравнивает её со своей, чтобы понять, нужно
// ли обновиться.
type Info struct {
	Version string `json:"version"`
	SingBox string `json:"singBox"`
	// Exe — путь к установленному vpnclient.exe.
	Exe string `json:"exe"`
	// Update — что сейчас с обновлением (для подсказки в окне).
	Update string `json:"update,omitempty"`
}

type SettingsView struct {
	Settings app.Settings `json:"settings"`
	OVPN     app.OVPNInfo `json:"ovpn"`
}

type importRequest struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

type nameRequest struct {
	Name string `json:"name"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// Server обслуживает запросы окна.
type Server struct {
	m    *app.Manager
	info func() Info
	// checkUpdate запускает проверку обновлений вне расписания.
	checkUpdate func()

	mu   sync.Mutex
	subs map[chan app.State]struct{}
}

func NewServer(info func() Info, checkUpdate func()) *Server {
	return &Server{info: info, checkUpdate: checkUpdate, subs: map[chan app.State]struct{}{}}
}

// SetManager подключает менеджер; до этого сервер умеет только Info.
func (s *Server) SetManager(m *app.Manager) { s.m = m }

// Broadcast рассылает состояние всем подписчикам. Передаётся в
// app.NewManager как onChange.
func (s *Server) Broadcast(st app.State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subs {
		// Медленный клиент пропускает промежуточные состояния, а не
		// тормозит службу.
		select {
		case ch <- st:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- st:
			default:
			}
		}
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", func(w http.ResponseWriter, r *http.Request) { reply(w, s.info(), nil) })
	mux.HandleFunc("GET /v1/state", func(w http.ResponseWriter, r *http.Request) { reply(w, s.m.State(), nil) })
	mux.HandleFunc("GET /v1/events", s.events)
	mux.HandleFunc("GET /v1/settings", func(w http.ResponseWriter, r *http.Request) {
		reply(w, SettingsView{Settings: s.m.Settings(), OVPN: s.m.OVPN()}, nil)
	})
	mux.HandleFunc("POST /v1/settings", func(w http.ResponseWriter, r *http.Request) {
		var settings app.Settings
		if err := decode(r, &settings); err != nil {
			reply(w, nil, err)
			return
		}
		reply(w, nil, s.m.SaveSettings(settings))
	})
	mux.HandleFunc("POST /v1/toggle", func(w http.ResponseWriter, r *http.Request) {
		s.m.Logf("IPC: переключение VPN из окна или трея")
		go s.m.Toggle()
		reply(w, nil, nil)
	})
	mux.HandleFunc("POST /v1/connect", func(w http.ResponseWriter, r *http.Request) {
		s.m.Connect()
		reply(w, nil, nil)
	})
	mux.HandleFunc("POST /v1/disconnect", func(w http.ResponseWriter, r *http.Request) {
		s.m.DisconnectWithReason("IPC: команда отключения из окна")
		reply(w, nil, nil)
	})
	mux.HandleFunc("POST /v1/ovpn", func(w http.ResponseWriter, r *http.Request) {
		var req importRequest
		if err := decode(r, &req); err != nil {
			reply(w, nil, err)
			return
		}
		info, err := s.m.ImportOVPN(req.Name, req.Data)
		reply(w, info, err)
	})
	mux.HandleFunc("DELETE /v1/ovpn", func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, s.m.RemoveOVPN())
	})
	mux.HandleFunc("POST /v1/server", func(w http.ResponseWriter, r *http.Request) {
		var req nameRequest
		if err := decode(r, &req); err != nil {
			reply(w, nil, err)
			return
		}
		reply(w, nil, s.m.SelectServer(req.Name))
	})
	mux.HandleFunc("POST /v1/test-servers", func(w http.ResponseWriter, r *http.Request) {
		s.m.TestServers()
		reply(w, nil, nil)
	})
	mux.HandleFunc("GET /v1/log", func(w http.ResponseWriter, r *http.Request) {
		data, err := s.m.Log(1 << 20)
		if err != nil {
			reply(w, nil, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/update", func(w http.ResponseWriter, r *http.Request) {
		if s.checkUpdate != nil {
			go s.checkUpdate()
		}
		reply(w, nil, nil)
	})
	return s.requireManager(mux)
}

func (s *Server) requireManager(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.m == nil && r.URL.Path != "/v1/info" {
			reply(w, nil, errors.New("служба запускается"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// events отдаёт поток состояний: по одной JSON-строке на изменение.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		reply(w, nil, errors.New("потоковая передача не поддерживается"))
		return
	}
	ch := make(chan app.State, 1)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	if err := enc.Encode(s.m.State()); err != nil {
		return
	}
	flusher.Flush()
	// Пустая строка раз в 15 секунд: так окно замечает, что служба
	// пропала, даже если состояние не меняется.
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case st := <-ch:
			if err := enc.Encode(st); err != nil {
				return
			}
		case <-ping.C:
			if _, err := w.Write([]byte("\n")); err != nil {
				return
			}
		}
		flusher.Flush()
	}
}

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(v); err != nil {
		return fmt.Errorf("неверный запрос: %w", err)
	}
	return nil
}

func reply(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: err.Error()})
		return
	}
	if v == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// Serve обслуживает соединения, пока не закроют listener.
func Serve(l net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	err := srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// ErrUnavailable — служба не отвечает (не установлена, остановлена,
// перезапускается).
var ErrUnavailable = errors.New("служба vpn-client недоступна")

// Client — сторона окна.
type Client struct {
	hc *http.Client
	// stream — без таймаута, для /v1/events.
	stream *http.Client
}

// NewClient создаёт клиента, который ходит через dial (named pipe на
// Windows, unix-сокет в тестах).
func NewClient(dial func(ctx context.Context) (net.Conn, error)) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
		Proxy:       nil,
	}
	return &Client{
		hc:     &http.Client{Transport: transport, Timeout: 30 * time.Second},
		stream: &http.Client{Transport: transport},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://vpn-client"+path, r)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e errorResponse
		if json.NewDecoder(resp.Body).Decode(&e) != nil || e.Error == "" {
			e.Error = resp.Status
		}
		return errors.New(e.Error)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) Info(ctx context.Context) (Info, error) {
	var v Info
	err := c.do(ctx, http.MethodGet, "/v1/info", nil, &v)
	return v, err
}

func (c *Client) State(ctx context.Context) (app.State, error) {
	var v app.State
	err := c.do(ctx, http.MethodGet, "/v1/state", nil, &v)
	return v, err
}

func (c *Client) Settings(ctx context.Context) (SettingsView, error) {
	var v SettingsView
	err := c.do(ctx, http.MethodGet, "/v1/settings", nil, &v)
	return v, err
}

func (c *Client) SaveSettings(ctx context.Context, s app.Settings) error {
	return c.do(ctx, http.MethodPost, "/v1/settings", s, nil)
}

func (c *Client) Toggle(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/toggle", nil, nil)
}

func (c *Client) Disconnect(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/disconnect", nil, nil)
}

func (c *Client) ImportOVPN(ctx context.Context, name string, data []byte) (app.OVPNInfo, error) {
	var v app.OVPNInfo
	err := c.do(ctx, http.MethodPost, "/v1/ovpn", importRequest{Name: name, Data: data}, &v)
	return v, err
}

func (c *Client) RemoveOVPN(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/v1/ovpn", nil, nil)
}

func (c *Client) SelectServer(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/v1/server", nameRequest{Name: name}, nil)
}

func (c *Client) TestServers(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/test-servers", nil, nil)
}

func (c *Client) CheckUpdate(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/update", nil, nil)
}

func (c *Client) Log(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://vpn-client/v1/log", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// Events вызывает fn на каждое новое состояние, пока поток не оборвётся
// или не отменят ctx.
func (c *Client) Events(ctx context.Context, fn func(app.State)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://vpn-client/v1/events", nil)
	if err != nil {
		return err
	}
	resp, err := c.stream.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s", ErrUnavailable, resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var st app.State
		if err := json.Unmarshal(line, &st); err == nil {
			fn(st)
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrUnavailable
}
