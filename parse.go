package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

func isURL(s string) bool { return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") }

func fetchLines(u string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpFetchTimeout); defer cancel()
	req, err := NewRequestWithUA(ctx, "GET", u)
	if err != nil { return nil, err }
	resp, err := httpClient().Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 { return nil, fmt.Errorf("http %d", resp.StatusCode) }
	lr := io.LimitReader(resp.Body, maxRemoteSize)
	sc := bufio.NewScanner(lr)
	var out []string
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln != "" { out = append(out, ln) }
	}
	return out, sc.Err()
}

// parseLine — распознаёт vmess/vless/trojan/ss строки
func parseLine(line string) (*ParsedConfig, error) {
	line = strings.TrimSpace(line)
	if line == "" { return nil, errors.New("empty") }

	// VMess (base64 json)
	if strings.HasPrefix(line, "vmess://") {
		b64 := strings.TrimPrefix(line, "vmess://")
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			if dec, derr := url.PathUnescape(b64); derr == nil {
				raw, err = base64.StdEncoding.DecodeString(dec)
			}
		}
		if err != nil { return &ParsedConfig{Raw: line, Scheme: "vmess", Note: "invalid-base64"}, nil }
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return &ParsedConfig{Raw: line, Scheme: "vmess", Note: "invalid-json"}, nil
		}
		pc := &ParsedConfig{ Raw: line, Scheme: "vmess" }
		str := func(k string) string { if v, ok := m[k].(string); ok { return v }; return "" }
		pc.Host = str("add"); pc.Port = str("port"); pc.Net = strings.ToLower(str("net")); pc.Path = str("path")
		pc.ID = str("id"); pc.HostHdr = str("host")
		if strings.ToLower(str("tls")) == "tls" { pc.TLS = true; pc.Security = "tls" } else { pc.Security = "none" }
		if pc.Net == "httpupgrade" { pc.Net = "ws" }
		return pc, nil
	}

	// SS (ss://)
	if strings.HasPrefix(line, "ss://") {
		return parseSS(line), nil
	}

	// Остальные как URL
	u, err := url.Parse(line)
	if err != nil || u.Scheme == "" {
		re := regexp.MustCompile(`([0-9a-zA-Z\.\-]+):([0-9]{1,5})`)
		if m := re.FindStringSubmatch(line); m != nil {
			return &ParsedConfig{Raw: line, Scheme: "unknown", Host: m[1], Port: m[2]}, nil
		}
		return &ParsedConfig{Raw: line, Scheme: "unknown", Note: "could-not-parse"}, nil
	}

	switch strings.ToLower(u.Scheme) {
	case "vless", "trojan":
		q := u.Query()
		pc := &ParsedConfig{
			Raw:        line,
			Scheme:     strings.ToLower(u.Scheme),
			Security:   strings.ToLower(q.Get("security")),
			Host:       u.Hostname(),
			Port:       u.Port(),
			Path:       u.Path,
			Net:        strings.ToLower(q.Get("type")),
			TLS:        strings.ToLower(q.Get("security")) == "tls",
			SNI:        q.Get("sni"),
			ID:         u.User.Username(),
			Alpn:       q.Get("alpn"),
			HostHdr:    q.Get("host"),
			PBK:        q.Get("pbk"),
			ShortID:    q.Get("sid"),
			SpiderX:    q.Get("spx"),
			Fingerprint: q.Get("fp"),
			Flow:        q.Get("flow"),
			Params:     q,
		}
		if pc.Net == "httpupgrade" { pc.Net = "ws" }
		if strings.Contains(pc.Net, "grpc") {
			pc.Note = "unsupported: grpc"
		}
		if pc.Security == "reality" && strings.Contains(pc.Net, "grpc") {
			pc.Note = "unsupported: reality/grpc"
		}
		return pc, nil
	default:
		return &ParsedConfig{Raw: line, Scheme: strings.ToLower(u.Scheme), Host: u.Hostname(), Port: u.Port()}, nil
	}
}

func parseSS(line string) *ParsedConfig {
	u, err := url.Parse(line)
	if err != nil { return &ParsedConfig{Raw: line, Scheme: "shadowsocks", Note: "parse-fail"} }
	credB64 := u.User.Username()
	dec, err := base64.StdEncoding.DecodeString(credB64)
	if err != nil { dec, _ = base64.RawStdEncoding.DecodeString(credB64) }
	method, pass := "", ""
	if len(dec) > 0 {
		parts := strings.SplitN(string(dec), ":", 2)
		if len(parts) == 2 { method, pass = parts[0], parts[1] }
	}
	q := u.Query()
	pc := &ParsedConfig{
		Raw:      line,
		Scheme:   "shadowsocks",
		Host:     u.Hostname(),
		Port:     u.Port(),
		Method:   method,
		Password: pass,
		Params:   q,
	}
	if plug := q.Get("plugin"); plug != "" {
		for _, seg := range strings.Split(plug, ";") {
			seg = strings.TrimSpace(seg)
			if seg == "" { continue }
			if seg == "tls" { pc.Security = "tls"; pc.TLS = true; continue }
			kv := strings.SplitN(seg, "=", 2)
			k := strings.ToLower(kv[0]); v := ""
			if len(kv) == 2 { v = kv[1] }
			switch k {
			case "mode":
				if strings.ToLower(v) == "websocket" { pc.Net = "ws" }
			case "host":
				pc.HostHdr = v
			case "path":
				if v == "" { v = "/" }
				pc.Path = v
			}
		}
	}
	if pc.Net == "" { pc.Net = "tcp" }
	return pc
}
