#!/usr/bin/env bash
set -euo pipefail

repository="T-Matrix/mmwx-guard"
public_url=""
listen="127.0.0.1:9080"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-url) public_url="${2:-}"; shift 2 ;;
    --listen) listen="${2:-}"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 或 sudo 执行安装命令" >&2
  exit 1
fi
if [[ ! "${public_url}" =~ ^https://[^/]+/?$ ]]; then
  echo "--public-url 必须是 HTTPS 地址，例如 https://guard.example.com" >&2
  exit 2
fi
public_url="${public_url%/}"
case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "暂不支持的架构: $(uname -m)" >&2; exit 1 ;;
esac

if ! command -v curl >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl coreutils
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl coreutils
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl coreutils
  else
    echo "请先安装 curl、ca-certificates 和 sha256sum" >&2
    exit 1
  fi
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
base="https://github.com/${repository}/releases/latest/download"
files=("mmwx-guard-linux-${arch}" "mmwx-guard-agent-linux-amd64" "mmwx-guard-agent-linux-arm64")
curl -fL --retry 3 --connect-timeout 10 "${base}/SHA256SUMS" -o "${tmpdir}/SHA256SUMS"
for file in "${files[@]}"; do
  curl -fL --retry 3 --connect-timeout 10 "${base}/${file}" -o "${tmpdir}/${file}"
  expected="$(awk -v name="${file}" '$2 == name { print $1 }' "${tmpdir}/SHA256SUMS")"
  actual="$(sha256sum "${tmpdir}/${file}" | awk '{ print $1 }')"
  if [[ -z "${expected}" || "${actual}" != "${expected}" ]]; then
    echo "${file} SHA-256 校验失败" >&2
    exit 1
  fi
  chmod 0755 "${tmpdir}/${file}"
done
version="$(${tmpdir}/mmwx-guard-linux-${arch} --version)"
if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  echo "主控版本自检失败: ${version}" >&2
  exit 1
fi

if ! id -u mmwx-guard >/dev/null 2>&1; then
  useradd --system --home /var/lib/mmwx-guard --shell /usr/sbin/nologin mmwx-guard
fi
install -d -o mmwx-guard -g mmwx-guard -m 0750 /var/lib/mmwx-guard /var/lib/mmwx-guard/update
install -d -o root -g root -m 0755 /usr/lib/mmwx-guard
install -d -o root -g mmwx-guard -m 0750 /etc/mmwx-guard
touch /etc/mmwx-guard/controller.env
chown root:mmwx-guard /etc/mmwx-guard/controller.env
chmod 0640 /etc/mmwx-guard/controller.env
systemctl stop mmwx-guard.service 2>/dev/null || true
install -m 0755 "${tmpdir}/mmwx-guard-linux-${arch}" /usr/local/bin/mmwx-guard
install -m 0755 "${tmpdir}/mmwx-guard-agent-linux-amd64" /usr/lib/mmwx-guard/mmwx-guard-agent-linux-amd64
install -m 0755 "${tmpdir}/mmwx-guard-agent-linux-arm64" /usr/lib/mmwx-guard/mmwx-guard-agent-linux-arm64

cat >/etc/systemd/system/mmwx-guard.service <<UNIT
[Unit]
Description=妙妙屋X安全防护 Controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mmwx-guard
Group=mmwx-guard
EnvironmentFile=-/etc/mmwx-guard/controller.env
ExecStart=/usr/local/bin/mmwx-guard --listen ${listen} --database /var/lib/mmwx-guard/controller.db --public-url ${public_url} --agent-dir /usr/lib/mmwx-guard --update-dir /var/lib/mmwx-guard/update --release-repo ${repository}
Restart=always
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
PrivateDevices=true
ReadWritePaths=/var/lib/mmwx-guard
StateDirectory=mmwx-guard
StateDirectoryMode=0750
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
MemoryDenyWriteExecute=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/mmwx-guard-update.path <<'UNIT'
[Unit]
Description=Watch for 妙妙屋X安全防护 controller update requests

[Path]
PathExists=/var/lib/mmwx-guard/update/request.json
Unit=mmwx-guard-update.service

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/mmwx-guard-update.service <<UNIT
[Unit]
Description=Apply a verified 妙妙屋X安全防护 controller update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/mmwx-guard --apply-update --release-repo ${repository} --update-dir /var/lib/mmwx-guard/update --install-path /usr/local/bin/mmwx-guard --agent-dir /usr/lib/mmwx-guard --service-name mmwx-guard.service --health-url http://${listen}/healthz
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/usr/local/bin /usr/lib/mmwx-guard /var/lib/mmwx-guard
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
RestrictSUIDSGID=true
UMask=0077
UNIT

systemctl daemon-reload
systemctl enable --now mmwx-guard.service mmwx-guard-update.path
echo "妙妙屋X安全防护 ${version} 安装完成"
