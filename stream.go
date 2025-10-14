package main

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
)

type streamer struct {
	mu         sync.Mutex
	fAll       *os.File
	wAll       *bufio.Writer
	fWork      *os.File
	wWork      *bufio.Writer
	seenWork   map[string]struct{}
	firstSaved int32
}

func newStreamer() (*streamer, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil { return nil, err }
	fAll, err := os.OpenFile(allOutFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil { return nil, err }
	fWork, err := os.OpenFile(workingFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil { fAll.Close(); return nil, err }
	return &streamer{
		fAll: fAll, wAll: bufio.NewWriter(fAll),
		fWork: fWork, wWork: bufio.NewWriter(fWork),
		seenWork: make(map[string]struct{}),
	}, nil
}
func (s *streamer) Close() {
	s.mu.Lock()
	if s.wAll != nil { _ = s.wAll.Flush() }
	if s.wWork != nil { _ = s.wWork.Flush() }
	if s.fAll != nil { _ = s.fAll.Close() }
	if s.fWork != nil { _ = s.fWork.Close() }
	s.mu.Unlock()
}
func (s *streamer) WriteResultLine(line string) {
	s.mu.Lock(); defer s.mu.Unlock()
	_, _ = s.wAll.WriteString(line + "\n")
	_ = s.wAll.Flush()
}
func (s *streamer) WriteWorkLine(line string) {
	s.mu.Lock(); defer s.mu.Unlock()
	if _, ok := s.seenWork[line]; ok { return }
	_, _ = s.wWork.WriteString(line + "\n")
	_ = s.wWork.Flush()
	s.seenWork[line] = struct{}{}
	if atomic.CompareAndSwapInt32(&s.firstSaved, 0, 1) {
		_ = os.WriteFile(firstOKFile, []byte(line+"\n"), 0o644)
	}
}

// ——— вспомогательные штуки для parse.go ———

func httpClient() *http.Client {
	return &http.Client{ Timeout: httpFetchTimeout }
}

func NewRequestWithUA(ctx context.Context, method, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil { return nil, err }
	req.Header.Set("User-Agent", "XrayChecker/1.2")
	return req, nil
}

func firstNonEmpty(a, b string) string { if a != "" { return a }; return b }

func atoiDefault(s string, d int) int {
	if s == "" { return d }
	var v int
	_, err := fmt.Sscan(s, &v)
	if err != nil || v <= 0 { return d }
	return v
}

func dedup(xs []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(xs))
	for _, s := range xs {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
