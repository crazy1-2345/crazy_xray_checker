package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

func quickTCPProbe(host, port string, timeout time.Duration) bool {
	if host == "" || port == "" { return true }
	d := net.Dialer{ Timeout: timeout }
	c, err := d.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil { return false }
	_ = c.Close()
	return true
}

var domainRe = regexp.MustCompile(`([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}`)

func extractSNICandidates(sni, hostHdr, fallbackHost string) []string {
	var cand []string
	push := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" { return }
		for _, x := range cand { if x == v { return } }
		cand = append(cand, v)
	}
	push(hostHdr)
	for _, m := range domainRe.FindAllString(sni, -1) { push(m) }
	if fallbackHost != "" && net.ParseIP(fallbackHost) == nil { push(fallbackHost) }
	if len(cand) == 0 && sni != "" { push(sni) }
	if len(cand) > 5 { cand = cand[:5] }
	return cand
}

func checkViaXray(pc *ParsedConfig) (string, bool) {
	if pc.Scheme != "vmess" && pc.Scheme != "vless" && pc.Scheme != "trojan" && pc.Scheme != "shadowsocks" {
		return "unsupported-scheme", false
	}
	if pc.Note != "" && strings.Contains(pc.Note, "unsupported") {
		return pc.Note, false
	}
	if strings.Contains(strings.ToLower(pc.Net), "grpc") {
		return "unsupported: grpc", false
	}

	// быстрый TCP-проб
	if enableTCPProbe {
		if !quickTCPProbe(pc.Host, firstNonEmpty(pc.Port, "443"), 800*time.Millisecond) {
			return "tcp-dead", false
		}
	}

	// перебор SNI (для кривых строк)
	sniCandidates := []string{pc.SNI}
	if strings.Count(pc.SNI, ".") >= 2 {
		sniCandidates = extractSNICandidates(pc.SNI, pc.HostHdr, pc.Host)
	}
	if len(sniCandidates) == 0 {
		sniCandidates = []string{pc.SNI}
	}

	attempts := 0
	var lastReason string

	for _, sni := range sniCandidates {
		attempts++

		// free socks port
		socksPort, l, err := pickFreePort()
		if err != nil { return "no-free-port", false }
		l.Close()

		// подмена SNI на попытку
		origSNI := pc.SNI
		pc.SNI = sni
		cfgJSON, err := buildXrayConfig(pc, socksPort)
		pc.SNI = origSNI
		if err != nil {
			lastReason = "build-config-fail: " + err.Error()
			continue
		}

		tmp, err := os.CreateTemp("", "xraycheck-*.json")
		if err != nil { return "tempfile-fail: " + err.Error(), false }
		_, _ = tmp.Write(cfgJSON); tmp.Close()
		defer os.Remove(tmp.Name())

		xrayBin := os.Getenv("XRAY_BIN")
		if xrayBin == "" { xrayBin = "xray" }
		ctx, cancel := context.WithTimeout(context.Background(), xrayRunBudget)
		cmd := exec.CommandContext(ctx, xrayBin, "-c", tmp.Name())
		var outBuf, errBuf bytes.Buffer
		cmd.Stdout = &outBuf; cmd.Stderr = &errBuf

		if err := cmd.Start(); err != nil {
			cancel()
			lastReason = "xray-start-fail: " + err.Error()
			continue
		}

		time.Sleep(bootWait)

		ok := doHTTPViaSocks(socksPort)
		if !ok {
			time.Sleep(300 * time.Millisecond)
			ok = doHTTPViaSocks(socksPort)
		}

		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		cancel()

		if ok { return "xray-ok", true }
		if tail := tailString(errBuf.String(), 180); tail != "" {
			lastReason = "xray-handshake-fail: " + tail
		} else {
			lastReason = "xray-handshake-fail"
		}
		if attempts >= retrySNI { break }
	}

	if lastReason == "" { lastReason = "xray-handshake-fail" }
	return lastReason, false
}

func doHTTPViaSocks(port int) bool {
	tb := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, &net.Dialer{
				Timeout:   testTimeout,
				KeepAlive: 0,
			})
			if err != nil { return nil, err }
			return d.(proxy.ContextDialer).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tb, Timeout: testTimeout}
	resp, err := client.Get(testURL)
	if err != nil { return false }
	io.Copy(io.Discard, resp.Body); resp.Body.Close()
	return true
}

func pickFreePort() (int, net.Listener, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { return 0, nil, err }
	return l.Addr().(*net.TCPAddr).Port, l, nil
}

func tailString(s string, n int) string {
	s = strings.TrimSpace(s); if s == "" { return "" }
	if len(s) <= n { return s }
	return s[len(s)-n:]
}
