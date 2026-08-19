# 安全说明与审计记录

最后审计：2026-08-19

## 系统边界

主控保存管理员会话、一次性 Agent 注册令牌、Agent 凭据哈希、策略和遥测。Agent 以 root 运行，但主控协议没有远程 Shell；可下发的命令仅限结构化 nftables 策略、回滚和版本更新。Agent 只主动连接主控，服务器无需为本系统开放入站管理端口。

## 已实施控制

- 管理接口使用 24 小时随机会话、`HttpOnly`、`SameSite=Strict`，HTTPS 下启用 `Secure`。
- 所有非只读管理请求、登录、退出和初始化都验证严格同源 `Origin` 或 `Referer`。
- 登录同时按来源 IP 和账号限制失败次数，Turnstile 服务端验证 `success`、`action=login` 和精确 hostname；上游错误时失败关闭。
- 代理来源头只从本机反代读取；只有反代观察到的上游命中显式 `TRUSTED_PROXY_CIDRS` 时才采信 Cloudflare 客户端地址。
- Agent 使用独立随机凭据，数据库只保存 SHA-256 哈希；WebSocket Hello 再校验注册机器的 Machine ID。
- 主控使用持久 Ed25519 身份签署每次握手；Agent 固定公钥，双方同时校验指纹，身份变化时拒绝连接。
- 每次连接使用临时 X25519、HKDF-SHA256 和方向独立的 AES-256-GCM 密钥。信封序号严格递增，拒绝篡改、重放与乱序。
- 控制消息包含随机 Request ID 和时间戳。Agent 拒绝过期、未来和重复命令；新 Agent 的策略、更新、遥测和换钥消息全部进入加密信封。
- Agent 凭据支持加密在线轮换、立即撤销和一次性重新配对。轮换在数据库中串行化，新凭据成功回连前保留旧凭据，避免并发换钥锁死。
- WebSocket 消息、遥测、注册字段和批量操作均有大小或数量上限；遥测写入和 Agent 重连分别节流。
- 防护策略经过结构验证、`nft -c` 预检和原子应用，失败时保留或恢复旧规则。
- systemd 限制文件系统、设备、内核接口和能力；普通 Agent 进程仅保留 `CAP_NET_ADMIN`。
- SQLite 使用 WAL、外键和单写连接；事件审计表自动保留约一万条最新记录。

## 部署检查

1. 主控只监听 `127.0.0.1:9080`，公网入口必须使用 HTTPS 反向代理。
2. `/etc/mmwx-guard/controller.env` 权限为 `root:mmwx-guard 0640`，Turnstile hostname 只包含实际生产域名。
3. `TRUSTED_PROXY_CIDRS` 使用 Cloudflare 官方当前网段并定期更新；源站直连请求不得依赖客户端自带的 `CF-Connecting-IP`。
4. `/etc/mmwx-guard/agent.json` 和 `/var/lib/mmwx-guard/agent-credentials.json` 权限为 `0600`，不得复制到其他机器或写入镜像。
5. 主控和 Agent 都启用 NTP，并监控超过 30 秒的时钟偏差。
6. 同时备份 `/var/lib/mmwx-guard/controller.db` 与 `/var/lib/mmwx-guard/controller-identity.key`，备份按凭据数据加密和限制访问。
7. Cloudflare 和 GitHub 管理员启用硬件或通行密钥 MFA，并限制 Release 发布权限。

## 更新信任边界

更新器固定 GitHub 仓库、版本格式和资产名，并校验 manifest 中的文件大小、SHA-256、主控二进制内置版本及更新后的健康状态。Agent 只从已认证主控下载与命令所声明哈希、大小一致的二进制。

当前 Release manifest 没有使用仓库之外的独立签名密钥。若 GitHub 仓库、Actions 工作流或 Release 发布权限失陷，攻击者可以同时替换二进制和哈希。这是当前最主要的剩余供应链风险。对该风险不可接受的环境应禁用在线更新，固定版本，并通过独立签名或内部制品仓库发布。

## 剩余风险

- Agent 需要 root 与 `CAP_NET_ADMIN`；Agent 二进制漏洞可能影响整台服务器。
- Machine ID 防止直接复制凭据，但不是硬件证明。已获得 root 的攻击者仍可能读取凭据并伪造机器标识。
- 主控是所有 Agent 的信任根。管理员会话或主控主机失陷后，攻击者可修改防护策略和发起受信更新。
- 首次注册仍以 HTTPS 和反向代理为初始信任根；若该链路在注册当时已被完全攻陷，攻击者可能替换初始固定公钥。主控指纹应通过独立渠道抽查。
- 为无中断升级保留的旧 Agent TLS 兼容模式没有应用层加密或主控身份固定，应尽快逐台升级并在面板消除兼容状态。
- Turnstile 和应用登录限速不是网络层 DDoS 防护；公网流量洪峰仍应由 Cloudflare、反代限速和上游防火墙吸收。
- 妙妙屋与 ForwardX 识别读取本机配置，只用于展示端口，不导入其中的远程控制能力或凭据。

## 漏洞报告

报告中不要包含生产凭据、Agent 配置或数据库。请提供受影响版本、复现步骤、预期影响和建议修复方向，并在公开披露前留出修复时间。
