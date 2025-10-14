package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type httpServer struct{ s *http.Server }

func (hs *httpServer) Shutdown() error {
	if hs == nil || hs.s == nil { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
	return hs.s.Shutdown(ctx)
}

type rescanReq struct {
	Max int `json:"max"` // скольких рабочих собрать (0 => по умолчанию, возьмём 25 на фронте)
}

var rescanMu sync.Mutex

func LoadAppConfig(path string) (AppConfig, error) {
	var cfg AppConfig
	cfg.APIKey = ""; cfg.Bind = ":8080"; cfg.Title = "V2/Xray Checker"
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			_ = writeDefaultConfig(path, cfg.Bind)
			return cfg, fmt.Errorf("config.json not found; created template with empty api_key")
		}
		return cfg, err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&cfg); err != nil { return cfg, err }
	if cfg.Bind == "" { cfg.Bind = ":8080" }
	return cfg, nil
}

func writeDefaultConfig(path, bind string) error {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := AppConfig{ APIKey: "", Bind: bind, Title: "V2/Xray Checker" }
	b, _ := json.MarshalIndent(tmp, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

func StartWebServer(cfg AppConfig) *httpServer {
	mux := http.NewServeMux()

	// статика из ./html
	fs := http.FileServer(http.Dir("html"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("html", "index.html"))
	})

	// ping
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(cfg.APIKey, r) { unauthorized(w); return }
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"running":%v}`, IsScanRunning())
	})

	// список рабочих (JSON)
	mux.HandleFunc("/api/working", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(cfg.APIKey, r) { unauthorized(w); return }
		lines, err := readLinesSafe(workingFile)
		if err != nil { http.Error(w, "not found", http.StatusNotFound); return }
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(struct {
			Count   int      `json:"count"`
			Items   []string `json:"items"`
			Running bool     `json:"running"`
			Updated int64    `json:"updated"`
		}{Count: len(lines), Items: lines, Running: IsScanRunning(), Updated: time.Now().Unix()})
	})

	// рескан: POST /api/rescan  { "max": 25 }
	mux.HandleFunc("/api/rescan", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(cfg.APIKey, r) { unauthorized(w); return }
		if r.Method != http.MethodPost { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }

		var req rescanReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Max < 0 { req.Max = 0 }

		if !TriggerRescan(req.Max) {
			http.Error(w, "already running", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"started":true,"max":%d}`, req.Max)
	})

	// RAW файлы
	mux.HandleFunc("/raw/working", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(cfg.APIKey, r) { unauthorized(w); return }
		serveRawFile(w, workingFile)
	})
	mux.HandleFunc("/raw/result", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(cfg.APIKey, r) { unauthorized(w); return }
		serveRawFile(w, allOutFile)
	})
	mux.HandleFunc("/raw/first", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(cfg.APIKey, r) { unauthorized(w); return }
		serveRawFile(w, firstOKFile)
	})

	s := &http.Server{ Addr: cfg.Bind, Handler: mux }
	fmt.Println("web server listening on", cfg.Bind)
	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Println("web server:", err)
		}
	}()
	return &httpServer{s: s}
}

func readLinesSafe(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil { return nil, err }
	raw := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		if s := strings.TrimSpace(l); s != "" { out = append(out, s) }
	}
	return out, nil
}

func serveRawFile(w http.ResponseWriter, path string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	f, err := os.Open(path)
	if err != nil { http.Error(w, "not found", http.StatusNotFound); return }
	defer f.Close()
	_, _ = io.Copy(w, f)
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	io.WriteString(w, "401 unauthorized\npass ?key=... or Authorization: Bearer <key>\n")
}

func checkAuth(apiKey string, r *http.Request) bool {
	if strings.TrimSpace(apiKey) == "" { return false }
	if auth := r.Header.Get("Authorization"); auth != "" {
		const p = "bearer "
		if len(auth) >= len(p) && strings.EqualFold(auth[:len(p)], p) {
			if strings.TrimSpace(auth[len(p):]) == apiKey { return true }
		}
	}
	return r.URL.Query().Get("key") == apiKey
}
