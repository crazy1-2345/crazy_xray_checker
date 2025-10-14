cat > install_go_xray.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# --- helpers ---
need_root() {
  if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo $0"
    exit 1
  fi
}
pkg_install() {
  if command -v apt >/dev/null 2>&1; then
    apt update -y
    apt install -y "$@"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$@"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$@"
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm "$@"
  else
    echo "Unsupported package manager. Install deps manually: curl tar unzip"
  fi
}
arch_go() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "amd64" ;; # fallback
  esac
}
arch_xray_asset() {
  case "$(uname -m)" in
    x86_64|amd64) echo "Xray-linux-64.zip" ;;
    aarch64|arm64) echo "Xray-linux-arm64-v8a.zip" ;;
    *) echo "Xray-linux-64.zip" ;; # fallback
  esac
}
# --- start ---
need_root
pkg_install curl tar unzip

# --- Install Go (latest) ---
GO_VER=$(curl -fsSL https://go.dev/VERSION?m=text | head -n1) # e.g. go1.23.3
GO_ARCH=$(arch_go)
GO_TGZ="${GO_VER}.linux-${GO_ARCH}.tar.gz"
echo "[Go] Installing ${GO_VER} for ${GO_ARCH} ..."
curl -fsSL -o "/tmp/${GO_TGZ}" "https://go.dev/dl/${GO_TGZ}"
rm -rf /usr/local/go
tar -C /usr/local -xzf "/tmp/${GO_TGZ}"
rm -f "/tmp/${GO_TGZ}"

# PATH for all users
mkdir -p /etc/profile.d
cat >/etc/profile.d/go.sh <<'EOP'
export PATH=/usr/local/go/bin:$PATH
EOP
chmod 644 /etc/profile.d/go.sh

# --- Install Xray (latest) ---
echo "[Xray] Fetching latest release info..."
ASSET_NAME=$(arch_xray_asset)
XRAY_URL=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest \
  | grep -Eo "\"browser_download_url\": *\"[^\"]*${ASSET_NAME}\"" \
  | head -n1 | sed -E 's/.*"browser_download_url": *"([^"]+)".*/\1/')
if [ -z "$XRAY_URL" ]; then
  echo "Could not resolve Xray asset URL. Check GitHub connectivity." >&2
  exit 1
fi
echo "[Xray] Downloading ${ASSET_NAME} ..."
curl -fsSL -o "/tmp/${ASSET_NAME}" "$XRAY_URL"
mkdir -p /usr/local/xray
unzip -o "/tmp/${ASSET_NAME}" -d /usr/local/xray >/dev/null
install -m 0755 /usr/local/xray/xray /usr/local/bin/xray
# geoip/geosite
mkdir -p /usr/local/share/xray
if [ -f /usr/local/xray/geoip.dat ]; then cp -f /usr/local/xray/geoip.dat /usr/local/share/xray/; fi
if [ -f /usr/local/xray/geosite.dat ]; then cp -f /usr/local/xray/geosite.dat /usr/local/share/xray/; fi
rm -f "/tmp/${ASSET_NAME}"

# --- Basic config & systemd ---
mkdir -p /etc/xray
if [ ! -f /etc/xray/config.json ]; then
  cat >/etc/xray/config.json <<'EOC'
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "socks-in", "port": 10808, "listen": "127.0.0.1", "protocol": "socks",
      "settings": { "udp": false, "auth": "noauth" } }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block",  "protocol": "blackhole" }
  ]
}
EOC
fi

cat >/etc/systemd/system/xray.service <<'EOS'
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray -c /etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOS

systemctl daemon-reload
systemctl enable xray --now || true

echo
echo "=== DONE ==="
echo "Reload your shell or run:  source /etc/profile.d/go.sh"
echo "Check versions:"
echo "  go version"
echo "  xray version"
echo
echo "Config path: /etc/xray/config.json"
echo "Service logs: journalctl -u xray -f"
EOF

chmod +x install_go_xray.sh
sudo ./install_go_xray.sh
