package controller

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (s *Server) handleInstallAgent(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="install-agent.sh"`)
	_, _ = w.Write([]byte(agentInstallScript))
}

func (s *Server) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.PathValue("filename")
	if filename != "mmwx-guard-agent-linux-amd64" && filename != "mmwx-guard-agent-linux-arm64" {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.agentDir, filename)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Disposition", `attachment; filename="mmwx-guard-agent"`)
	http.ServeFile(w, r, path)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

const agentInstallScript = `#!/usr/bin/env bash
set -euo pipefail

controller=""
token=""
name=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --controller) controller="${2:-}"; shift 2 ;;
    --token) token="${2:-}"; shift 2 ;;
    --name) name="${2:-}"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 或 sudo 执行安装命令" >&2
  exit 1
fi
if [[ -z "${controller}" || -z "${token}" ]]; then
  echo "缺少 --controller 或 --token" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Agent 仅支持 Linux" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "暂不支持的架构: $(uname -m)" >&2; exit 1 ;;
esac

if ! command -v curl >/dev/null 2>&1 || ! command -v nft >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl nftables
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl nftables
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl nftables
  else
    echo "请先安装 curl、ca-certificates 和 nftables" >&2
    exit 1
  fi
fi

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
curl -fL --retry 3 --connect-timeout 10 \
  "${controller%/}/downloads/mmwx-guard-agent-linux-${arch}" -o "${tmp}"
chmod 0755 "${tmp}"

systemctl stop mmwx-guard-protection-agent.service 2>/dev/null || true
install -d -m 0700 /etc/mmwx-guard /var/lib/mmwx-guard
install -m 0755 "${tmp}" /usr/local/bin/mmwx-guard-agent

/usr/local/bin/mmwx-guard-agent \
  --enroll-only \
  --controller "${controller}" \
  --token "${token}" \
  --name "${name}"

cat >/etc/systemd/system/mmwx-guard-protection-agent.service <<'UNIT'
[Unit]
Description=妙妙屋X安全防护 Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mmwx-guard-agent --config /etc/mmwx-guard/agent.json --state-dir /var/lib/mmwx-guard
Restart=always
RestartSec=3s
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/mmwx-guard-protection-agent-update.path <<'UNIT'
[Unit]
Description=Watch for 妙妙屋X安全防护 Agent update requests

[Path]
PathExists=/var/lib/mmwx-guard/agent-update/request.json
Unit=mmwx-guard-protection-agent-update.service

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/mmwx-guard-protection-agent-update.service <<'UNIT'
[Unit]
Description=Apply a verified 妙妙屋X安全防护 Agent update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/mmwx-guard-agent --apply-agent-update --state-dir /var/lib/mmwx-guard --install-path /usr/local/bin/mmwx-guard-agent --service-name mmwx-guard-protection-agent.service
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/usr/local/bin /var/lib/mmwx-guard
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
UNIT

systemctl daemon-reload
systemctl enable --now mmwx-guard-protection-agent.service mmwx-guard-protection-agent-update.path
echo "妙妙屋X安全防护 Agent 安装完成"
`
