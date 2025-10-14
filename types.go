package main

import (
	"net/url"
)

// ParsedConfig — нормализованная запись строки
type ParsedConfig struct {
	Raw        string
	Scheme     string // vmess, vless, trojan, shadowsocks
	Security   string // tls, reality, none
	Host       string
	Port       string
	Net        string // tcp, ws, httpupgrade, grpc, xhttp...
	Path       string
	TLS        bool // convenience
	SNI        string
	ID         string // vmess/vless uuid или trojan password
	Method     string // shadowsocks method
	Password   string // shadowsocks password
	Alpn       string
	HostHdr    string
	PBK        string // reality publicKey
	ShortID    string // reality shortId (sid)
	SpiderX    string // reality spiderX (spx)
	Fingerprint string // reality fingerprint (fp)
	Flow       string  // e.g. xtls-rprx-vision
	Params     url.Values
	Note       string
}

// Result — итог проверки одной строки
type Result struct {
	Line   string
	Parsed *ParsedConfig
	OK     bool
	Reason string
}
