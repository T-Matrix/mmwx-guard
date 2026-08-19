# 妙妙屋X安全防护

面向多台 Linux 转发服务器的独立连接洪峰防护主控与 Agent。Agent 主动连接主控，不需要开放远程管理端口；主控只能下发结构化防护策略和经过校验的版本更新，不提供远程 Shell。

## 功能

- 多服务器 Agent 注册、在线状态和连接遥测
- 识别每台机器的妙妙屋 Xray 节点端口与 ForwardX 转发入口
- 服务器详情内独立配置防护，修改不会影响其他机器
- 按端口单 IP、端口总量与整机 SYN 弹性限流
- nftables 语法预检、原子应用、失败回滚和规则自动补回
- GitHub Release 主控自更新，健康检查失败自动回滚
- 面板批量更新 Agent，未重新上线时自动回滚
- SQLite 管理员、会话、一次性注册令牌与事件审计

## 安装主控

需要 Linux amd64/arm64、systemd 和一个已经反向代理到 `127.0.0.1:9080` 的 HTTPS 域名。

```bash
curl -fL https://github.com/T-Matrix/mmwx-guard/releases/latest/download/install-controller.sh \
  | sudo bash -s -- --public-url https://guard.example.com
```

Caddy 示例：

```caddy
guard.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:9080
}
```

首次打开网页后创建管理员。进入“服务器管理”，生成一次性命令并在目标服务器执行即可安装 Agent。

## Cloudflare Turnstile

生产环境建议在登录和首次初始化页面启用 Turnstile。三个变量必须同时写入主控的 `/etc/mmwx-guard/controller.env`，缺少任意一项时主控会拒绝启动：

```ini
TURNSTILE_SITE_KEY=your-site-key
TURNSTILE_SECRET=your-widget-secret
TURNSTILE_HOSTNAMES=guard.example.com
```

代理网段另行使用逗号分隔配置，例如 `TRUSTED_PROXY_CIDRS=173.245.48.0/20,103.21.244.0/22`；生产应填写 Cloudflare 公布的完整 IPv4 和 IPv6 列表。

`TURNSTILE_HOSTNAMES` 必须是浏览器实际访问的主机名，不含协议、端口或路径。生产环境不要加入 `localhost` 或 `127.0.0.1`。修改后执行 `systemctl restart mmwx-guard`。

主控只读取来自本机回环地址反代的代理头。只有 `X-Forwarded-For` 的直接上游命中 `TRUSTED_PROXY_CIDRS` 时才采信 `CF-Connecting-IP`；否则使用反代观察到的直接来源，防止绕过 Cloudflare 直连源站时伪造 IP。Cloudflare 网段应从 `https://www.cloudflare.com/ips/` 获取并定期更新。Caddy 或 Nginx 必须与主控位于同一台机器，并只把主控暴露在 `127.0.0.1:9080`。

## 更新

点击右上角管理员头像，进入“版本更新”：

1. 主控从 `T-Matrix/mmwx-guard` 的最新 GitHub Release 读取 `manifest.json`。
2. 更新器核对文件大小、SHA-256 和二进制内置版本，再原子替换。
3. 主控更新后，可选择在线且版本落后的 Agent 批量更新。
4. 主控健康检查或 Agent 重新上线检查失败时，自动恢复 `.previous` 版本。

SHA-256 来自同一个 GitHub Release，它用于校验下载完整性，不是独立发布签名。GitHub 仓库或 Release 发布权限失陷时仍可能产生带有匹配哈希的恶意版本；高安全环境应关闭面板在线更新，固定审核过的版本并通过自己的制品签名流程部署。

## 开发

```bash
cd web
pnpm install
pnpm build
cd ..
go test ./...
go vet ./...
```

发布由 `.github/workflows/release.yml` 完成。推送 `v*` 标签后会构建 Linux amd64/arm64 主控和 Agent、生成 `SHA256SUMS` 与 `manifest.json`，并创建 GitHub Release。

## 安全边界

- Agent 以 root 运行，仅用于读取内核遥测和管理专属 nftables 表。
- Agent 凭据保存在 `/etc/mmwx-guard/agent.json`，权限为 `0600`。
- 每份 Agent 凭据与首次注册机器的 Machine ID 绑定，复制 `agent.json` 到另一台机器会被主控拒绝。迁移机器时应删除旧记录并重新注册。
- 新 Agent 使用独立的 `mmwx-guard-protection-agent.service`，不会覆盖妙妙屋原有 Agent 或授权守卫服务。
- 更新请求只能引用固定发布仓库、语义版本和固定资产名。
- 防护策略下发前运行 `nft -c`；安装 Agent 本身不会自动启用任何防护策略。
- 主控和所有 Agent 必须启用 NTP。控制消息允许最多 30 秒未来偏差，并拒绝超过 2 分钟的消息。
- Agent WebSocket 消息限制为 256 KiB，遥测会校验数值、数组和字符串边界，并按服务器节流写入。

完整威胁模型、部署检查项和剩余风险见 [SECURITY.md](SECURITY.md)。

本项目采用 MIT License。复用资源的许可见 `THIRD_PARTY_NOTICES.md`。
