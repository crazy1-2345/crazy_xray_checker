package main

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
)

func defaultPortFor(pc *ParsedConfig) int {
	switch pc.Security {
	case "tls", "reality":
		return 443
	}
	if pc.Net == "ws" { return 80 }
	return 443
}

func buildXrayConfig(pc *ParsedConfig, socksPort int) ([]byte, error) {
	type Obj = map[string]any

	stream := Obj{}
	// network
	netw := pc.Net
	if netw == "" {
		if pc.Path != "" { netw = "ws" } else { netw = "tcp" }
	}
	if pc.Security == "reality" { netw = "tcp" } // REALITY только tcp
	stream["network"] = netw

	// security
	switch pc.Security {
	case "tls":
		stream["security"] = "tls"
		tlsSettings := Obj{"allowInsecure": true}
		if pc.SNI != "" {
			tlsSettings["serverName"] = pc.SNI
		} else if net.ParseIP(pc.Host) == nil && pc.Host != "" {
			tlsSettings["serverName"] = pc.Host
		}
		if pc.Alpn != "" { tlsSettings["alpn"] = strings.Split(pc.Alpn, ",") }
		stream["tlsSettings"] = tlsSettings
	case "reality":
		stream["security"] = "reality"
		reality := Obj{
			"serverName":  pc.SNI,
			"publicKey":   pc.PBK,
			"shortId":     pc.ShortID,
			"spiderX":     firstNonEmpty(pc.SpiderX, "/"),
			"fingerprint": firstNonEmpty(pc.Fingerprint, "chrome"),
		}
		stream["realitySettings"] = reality
	}

	// ws settings
	if netw == "ws" {
		ws := Obj{"path": pc.Path}
		if pc.HostHdr != "" { ws["headers"] = Obj{"Host": pc.HostHdr} }
		stream["wsSettings"] = ws
	}

	out := Obj{"tag": "tested", "protocol": "", "settings": Obj{}}

	switch pc.Scheme {
	case "vmess":
		out["protocol"] = "vmess"
		out["settings"] = Obj{
			"vnext": []any{ Obj{
				"address": pc.Host,
				"port":    atoiDefault(pc.Port, defaultPortFor(pc)),
				"users": []any{ Obj{"id": pc.ID, "security": "auto"} },
			}},
		}
	case "vless":
		out["protocol"] = "vless"
		user := Obj{"id": pc.ID, "encryption": "none"}
		if pc.Security == "reality" || strings.Contains(strings.ToLower(pc.Flow), "vision") {
			user["flow"] = "xtls-rprx-vision"
		}
		out["settings"] = Obj{
			"vnext": []any{ Obj{
				"address": pc.Host,
				"port":    atoiDefault(pc.Port, defaultPortFor(pc)),
				"users":   []any{ user },
			}},
		}
	case "trojan":
		out["protocol"] = "trojan"
		out["settings"] = Obj{
			"servers": []any{ Obj{
				"address":  pc.Host,
				"port":     atoiDefault(pc.Port, defaultPortFor(pc)),
				"password": pc.ID,
				"ota":      false,
			}},
		}
	case "shadowsocks":
		out["protocol"] = "shadowsocks"
		out["settings"] = Obj{
			"servers": []any{ Obj{
				"address":  pc.Host,
				"port":     atoiDefault(pc.Port, defaultPortFor(pc)),
				"method":   pc.Method,
				"password": pc.Password,
			}},
		}
	default:
		return nil, errors.New("unsupported scheme: " + pc.Scheme)
	}

	cfg := Obj{
		"inbounds": []any{
			Obj{
				"tag":      "socks-in",
				"port":     socksPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": Obj{"udp": false, "auth": "noauth"},
			},
		},
		"outbounds": []any{
			out,
			Obj{"tag": "direct", "protocol": "freedom"},
			Obj{"tag": "block", "protocol": "blackhole"},
		},
	}

	out["streamSettings"] = stream
	return json.Marshal(cfg)
}
