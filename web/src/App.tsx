import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, Check, ChevronDown, CircleGauge, Clipboard, Copy,
  Cpu, Download, ExternalLink, FileClock, Filter, ListFilter, LogOut, Moon,
  Network, PackageCheck, Pencil, Plus, RefreshCw, Server, ShieldCheck, ShieldX, Sun,
  Trash2, X, Zap,
} from 'lucide-react'
import { api } from './api'
import type { Agent, EventItem, Policy, PortRule, SourceCount, Status as SystemStatus, UpdateInfo } from './api'

type Tab = 'overview' | 'agents' | 'policies' | 'events' | 'updates'
type Summary = { agents_total: number; agents_online: number; sockets: number; conntrack: number; dropped: number; protected: number }

const defaultSummary: Summary = { agents_total: 0, agents_online: 0, sockets: 0, conntrack: 0, dropped: 0, protected: 0 }

function App() {
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [tab, setTab] = useState<Tab>('overview')
  const [summary, setSummary] = useState<Summary>(defaultSummary)
  const [agents, setAgents] = useState<Agent[]>([])
  const [policies, setPolicies] = useState<Policy[]>([])
  const [events, setEvents] = useState<EventItem[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [enrollOpen, setEnrollOpen] = useState(false)
  const [policyOpen, setPolicyOpen] = useState(false)
  const [deployPolicy, setDeployPolicy] = useState<Policy | null>(null)
  const [renameAgent, setRenameAgent] = useState<Agent | null>(null)
  const [theme, setTheme] = useState(() => localStorage.getItem('mmwx-guard-theme') || 'pixel')

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('mmwx-guard-theme', theme)
  }, [theme])

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await api<SystemStatus>('/api/status'))
    } catch (e) {
      setError((e as Error).message)
    }
  }, [])

  const refresh = useCallback(async (silent = false) => {
    if (!silent) setBusy(true)
    try {
      const [nextSummary, agentResult, policyResult, eventResult] = await Promise.all([
        api<Summary>('/api/admin/summary'),
        api<{ agents: Agent[] }>('/api/admin/agents'),
        api<{ policies: Policy[] }>('/api/admin/policies'),
        api<{ events: EventItem[] }>('/api/admin/events'),
      ])
      setSummary(nextSummary)
      setAgents(agentResult.agents || [])
      setPolicies(policyResult.policies || [])
      setEvents(eventResult.events || [])
      setError('')
    } catch (e) {
      const message = (e as Error).message
      setError(message)
      if (message.includes('登录')) await loadStatus()
    } finally {
      if (!silent) setBusy(false)
    }
  }, [loadStatus])

  useEffect(() => { void loadStatus() }, [loadStatus])
  useEffect(() => {
    if (!status?.authenticated) return
    void refresh()
    const timer = window.setInterval(() => void refresh(true), 5000)
    return () => window.clearInterval(timer)
  }, [status?.authenticated, refresh])

  if (!status) return <LoadingScreen />
  if (!status.setup || !status.authenticated) {
    return <AuthScreen setup={!status.setup} onAuthenticated={loadStatus} />
  }

  const logout = async () => {
    await api('/api/logout', { method: 'POST', body: '{}' })
    setStatus({ ...status, authenticated: false, admin: '' })
  }

  return (
    <div className="app-shell">
      <Header tab={tab} setTab={setTab} theme={theme} setTheme={setTheme} admin={status.admin} onLogout={logout} />
      <main className="content">
        {error && <div className="alert-strip"><AlertTriangle size={18} />{error}<button onClick={() => setError('')} aria-label="关闭"><X size={16} /></button></div>}
        {tab === 'overview' && <Overview summary={summary} agents={agents} events={events} />}
        {tab === 'agents' && <Agents agents={agents} policies={policies} onEnroll={() => setEnrollOpen(true)} onDeploy={setDeployPolicy} onRename={setRenameAgent} onDelete={async id => { await api(`/api/admin/agents/${id}`, { method: 'DELETE' }); void refresh() }} />}
        {tab === 'policies' && <Policies policies={policies} agents={agents} onCreate={() => setPolicyOpen(true)} onDeploy={setDeployPolicy} />}
        {tab === 'events' && <Events events={events} agents={agents} />}
        {tab === 'updates' && <Updates currentVersion={status.version} agents={agents} onRefresh={() => void refresh(true)} />}
      </main>
      {enrollOpen && <EnrollmentDialog onClose={() => setEnrollOpen(false)} />}
      {renameAgent && <RenameAgentDialog agent={renameAgent} onClose={() => setRenameAgent(null)} onSaved={() => { setRenameAgent(null); void refresh() }} />}
      {policyOpen && <PolicyDialog onClose={() => setPolicyOpen(false)} onSaved={() => { setPolicyOpen(false); void refresh() }} />}
      {deployPolicy && <DeployDialog policy={deployPolicy} agents={agents} onClose={() => setDeployPolicy(null)} onDone={() => { setDeployPolicy(null); void refresh() }} />}
    </div>
  )
}

function Header({ tab, setTab, theme, setTheme, admin, onLogout }: { tab: Tab; setTab: (tab: Tab) => void; theme: string; setTheme: (theme: string) => void; admin: string; onLogout: () => void }) {
  const items: { id: Tab; label: string; icon: typeof Activity }[] = [
    { id: 'overview', label: '安全概览', icon: Activity },
    { id: 'agents', label: '服务器管理', icon: Server },
    { id: 'policies', label: '防护策略', icon: ShieldCheck },
    { id: 'events', label: '拦截记录', icon: ListFilter },
    { id: 'updates', label: '版本更新', icon: PackageCheck },
  ]
  return (
    <header className="topbar">
      <button className="brand" onClick={() => setTab('overview')}>
        <img className="brand-logo" src="/images/logo.webp" alt="妙妙屋 Logo" />
        <span>妙妙屋X安全防护</span>
      </button>
      <nav className="nav-tabs" aria-label="主导航">
        {items.map(item => <button key={item.id} className={tab === item.id ? 'active' : ''} onClick={() => setTab(item.id)} title={item.label} aria-label={item.label}><item.icon size={18} /><span>{item.label}</span></button>)}
      </nav>
      <div className="top-actions">
        <button className="theme-button" onClick={() => setTheme(theme === 'pixel' ? 'gold' : 'pixel')} title="切换主题" aria-label="切换主题">
          {theme === 'pixel' ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        <div className="admin-menu"><img className="avatar" src="/images/admin-avatar.webp" alt="管理员头像" /><span><strong>{admin}</strong><small>ADMIN</small></span><ChevronDown size={16} /></div>
        <button className="icon-button" onClick={onLogout} title="退出登录" aria-label="退出登录"><LogOut size={19} /></button>
      </div>
    </header>
  )
}

function PageTitle({ tab, busy, onRefresh }: { tab: Tab; busy: boolean; onRefresh: () => void }) {
  const titles: Record<Tab, [string, string]> = {
    overview: ['安全概览', '所有服务器的实时连接与防护状态'],
    agents: ['服务器管理', '注册、查看并批量管理安全防护 Agent'],
    policies: ['防护策略', '设置弹性阈值、可信入口和失败连接回收'],
    events: ['拦截记录', '策略下发、服务器状态和安全事件审计'],
    updates: ['版本更新', '从 GitHub Release 更新主控并批量升级 Agent'],
  }
  return <div className="page-heading"><div><h1>{titles[tab][0]}</h1><p>{titles[tab][1]}</p></div><button className="icon-button refresh" onClick={onRefresh} title="刷新" aria-label="刷新"><RefreshCw size={19} className={busy ? 'spin' : ''} /></button></div>
}

function Overview({ summary, agents, events }: { summary: Summary; agents: Agent[]; events: EventItem[] }) {
  const sources = useMemo(() => aggregateSources(agents), [agents])
  const maxSource = Math.max(1, ...sources.map(s => s.connections + (s.dropped || 0)))
  return <>
    <section className="metric-grid" aria-label="核心指标">
      <Metric icon={<Server />} title="在线服务器" value={`${summary.agents_online} / ${summary.agents_total}`} detail={`${summary.protected} 台已启用防护`} tone="coral" />
      <Metric icon={<Network />} title="当前连接" value={formatNumber(summary.sockets)} detail="所有服务器 TCP socket" tone="blue" />
      <Metric icon={<CircleGauge />} title="连接跟踪" value={formatNumber(summary.conntrack)} detail="内核 conntrack 当前记录" tone="amber" />
      <Metric icon={<ShieldX />} title="累计拦截" value={formatNumber(summary.dropped)} detail="超额新建连接已丢弃" tone="red" />
    </section>
    <section className="overview-grid">
      <div className="panel source-panel">
        <PanelHeader icon={<Zap size={21} />} title="高频来源" subtitle="按当前连接与最近拦截量排序" />
        {sources.length === 0 ? <Empty text="Agent 上线后会显示来源 IP" /> : <div className="source-list">{sources.slice(0, 8).map((source, i) => {
          const total = source.connections + (source.dropped || 0)
          return <div className="source-row" key={source.ip}><span className="rank">{String(i + 1).padStart(2, '0')}</span><span className="source-ip">{source.ip}</span><span className="source-bar"><i style={{ width: `${Math.max(3, total / maxSource * 100)}%` }} /></span><span className="source-values"><strong>{formatNumber(source.connections)}</strong><small>{formatNumber(source.dropped || 0)} 丢弃</small></span></div>
        })}</div>}
      </div>
      <div className="panel event-panel">
        <PanelHeader icon={<FileClock size={21} />} title="最近事件" subtitle="策略与 Agent 状态变更" />
        <div className="compact-events">{events.slice(0, 7).map(event => <div key={event.id}><StatusDot level={event.level} /><span>{event.message}</span><time>{relativeTime(event.created_at)}</time></div>)}{events.length === 0 && <Empty text="暂无事件" />}</div>
      </div>
    </section>
    <section className="panel fleet-panel">
      <PanelHeader icon={<Cpu size={21} />} title="服务器状态" subtitle="实时负载、内存和连接压力" />
      <div className="table-wrap"><table><thead><tr><th>服务器</th><th>状态</th><th>IP 地址</th><th>负载</th><th>内存</th><th>连接</th><th>拦截</th><th>策略</th></tr></thead><tbody>
        {agents.map(agent => <tr key={agent.id}><td><strong>{agent.name}</strong><small>{agent.os} / {agent.arch}</small></td><td><Status status={agent.status} protected={agent.telemetry?.protected} /></td><td className="mono">{agent.ip_address || '-'}</td><td>{agent.telemetry ? agent.telemetry.load_1.toFixed(2) : '-'}</td><td>{agent.telemetry ? percentage(agent.telemetry.memory_used, agent.telemetry.memory_total) : '-'}</td><td>{formatNumber(agent.telemetry?.sockets.total || 0)}</td><td className="danger-text">{formatNumber(agent.telemetry?.dropped_total || 0)}</td><td>{agent.policy_name || '未下发'}</td></tr>)}
        {agents.length === 0 && <tr><td colSpan={8}><Empty text="还没有服务器，前往服务器管理添加第一台" /></td></tr>}
      </tbody></table></div>
    </section>
  </>
}

function Agents({ agents, policies, onEnroll, onDeploy, onRename, onDelete }: { agents: Agent[]; policies: Policy[]; onEnroll: () => void; onDeploy: (p: Policy) => void; onRename: (agent: Agent) => void; onDelete: (id: string) => Promise<void> }) {
  return <section className="panel management-panel">
    <div className="section-toolbar"><div><h2>服务器列表 ({agents.length})</h2><p>Agent 使用主动连接，不需要向公网开放管理端口</p></div><button className="primary-button" onClick={onEnroll}><Plus size={18} />添加服务器</button></div>
    <div className="table-wrap"><table className="agent-table"><thead><tr><th>名称</th><th>连接状态</th><th>公网 IP</th><th>CPU</th><th>内存</th><th>Socket</th><th>SYN 堆积</th><th>Conntrack</th><th>防护策略</th><th>操作</th></tr></thead><tbody>
      {agents.map(agent => <tr key={agent.id}><td><strong>{agent.name}</strong><small>Agent {agent.version || '-'}</small></td><td><Status status={agent.status} protected={agent.telemetry?.protected} /></td><td className="mono">{agent.ip_address || '-'}</td><td>{agent.telemetry?.cpu_usage == null ? '-' : `${agent.telemetry.cpu_usage.toFixed(1)}%`}</td><td className="resource-cell"><strong>{agent.telemetry ? percentage(agent.telemetry.memory_used, agent.telemetry.memory_total) : '-'}</strong><small>{agent.telemetry ? `${formatMemory(agent.telemetry.memory_used)} / ${formatMemory(agent.telemetry.memory_total)}` : '-'}</small></td><td>{formatNumber(agent.telemetry?.sockets.total || 0)}</td><td>{(agent.telemetry?.sockets.syn_recv || 0) + (agent.telemetry?.sockets.syn_sent || 0)}</td><td>{formatNumber(agent.telemetry?.conntrack || 0)}</td><td>{agent.policy_name || <span className="muted">未下发</span>}</td><td><div className="row-actions">{policies[0] && <button title="下发策略" onClick={() => onDeploy(policies[0])}><ShieldCheck size={18} /></button>}<button title="修改名称" onClick={() => onRename(agent)}><Pencil size={18} /></button><button title="删除" className="danger" onClick={() => void onDelete(agent.id)}><Trash2 size={18} /></button></div></td></tr>)}
      {agents.length === 0 && <tr><td colSpan={10}><Empty text="点击“添加服务器”生成一次性安装命令" /></td></tr>}
    </tbody></table></div>
  </section>
}

function Policies({ policies, agents, onCreate, onDeploy }: { policies: Policy[]; agents: Agent[]; onCreate: () => void; onDeploy: (p: Policy) => void }) {
  return <section className="panel management-panel">
    <div className="section-toolbar"><div><h2>策略列表 ({policies.length})</h2><p>超过弹性额度时只丢新握手，已有连接不受影响</p></div><button className="primary-button" onClick={onCreate}><Plus size={18} />新建策略</button></div>
    <div className="policy-list">{policies.map(policy => <article className="policy-item" key={policy.id}>
      <div className="policy-icon"><ShieldCheck size={27} /></div><div className="policy-main"><div><h3>{policy.name}</h3><span>REV {policy.revision}</span></div><p>{(policy.ports || []).filter(p => p.enabled).map(p => `TCP ${p.port}`).join(' · ') || '未配置端口'}</p><div className="policy-stats"><span>单IP <strong>{policy.ports?.[0]?.per_ip_rate || 0}/s</strong></span><span>整端口 <strong>{policy.ports?.[0]?.aggregate_rate || 0}/s</strong></span><span>全局 <strong>{policy.global.enabled ? `${policy.global.rate}/s` : '关闭'}</strong></span><span>可信入口 <strong>{policy.trusted_cidrs?.length || 0}</strong></span></div></div>
      <button className="secondary-button" disabled={!agents.some(a => a.status === 'online')} onClick={() => onDeploy(policy)}><Zap size={17} />批量下发</button>
    </article>)}</div>
  </section>
}

function Events({ events, agents }: { events: EventItem[]; agents: Agent[] }) {
  const names = Object.fromEntries(agents.map(a => [a.id, a.name]))
  return <section className="panel management-panel"><div className="section-toolbar"><div><h2>安全事件 ({events.length})</h2><p>保留策略下发结果与 Agent 生命周期记录</p></div><button className="secondary-button"><Filter size={17} />全部事件</button></div>
    <div className="table-wrap"><table><thead><tr><th>级别</th><th>时间</th><th>事件</th><th>服务器</th><th>类型</th></tr></thead><tbody>{events.map(event => <tr key={event.id}><td><EventLevel level={event.level} /></td><td>{formatTime(event.created_at)}</td><td>{event.message}</td><td>{names[event.agent_id || ''] || event.agent_id || '-'}</td><td className="mono">{event.kind}</td></tr>)}{events.length === 0 && <tr><td colSpan={5}><Empty text="暂无事件" /></td></tr>}</tbody></table></div>
  </section>
}

function Updates({ currentVersion, agents, onRefresh }: { currentVersion: string; agents: Agent[]; onRefresh: () => void }) {
  const [info, setInfo] = useState<UpdateInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [confirmController, setConfirmController] = useState(false)
  const [controllerBusy, setControllerBusy] = useState(false)
  const candidates = agents.filter(agent => agent.status === 'online' && agent.version !== currentVersion)
  const candidateKey = candidates.map(agent => agent.id).join('|')
  const [selected, setSelected] = useState<string[]>([])
  const [agentBusy, setAgentBusy] = useState(false)
  const [results, setResults] = useState<{ agent_id: string; success: boolean; message: string }[]>([])

  const check = useCallback(async () => {
    setLoading(true); setError('')
    try { setInfo(await api<UpdateInfo>('/api/admin/update')) }
    catch (err) { setError((err as Error).message) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { void check() }, [check])
  useEffect(() => { setSelected(candidates.map(agent => agent.id)) }, [currentVersion, candidateKey])

  const updateController = async () => {
    if (!info?.latest_version) return
    setControllerBusy(true); setError('')
    try {
      const status = await api<UpdateInfo['status']>('/api/admin/update/controller', { method: 'POST', body: JSON.stringify({ version: info.latest_version }) })
      setInfo(value => value ? { ...value, status } : value)
      setConfirmController(false)
      window.setTimeout(() => window.location.reload(), 12000)
    } catch (err) { setError((err as Error).message) }
    finally { setControllerBusy(false) }
  }

  const updateAgents = async () => {
    setAgentBusy(true); setError(''); setResults([])
    try {
      const data = await api<{ version: string; results: { agent_id: string; success: boolean; message: string }[] }>('/api/admin/update/agents', { method: 'POST', body: JSON.stringify({ agent_ids: selected }) })
      setResults(data.results || [])
      window.setTimeout(() => { onRefresh(); void check() }, 8000)
    } catch (err) { setError((err as Error).message) }
    finally { setAgentBusy(false) }
  }

  return <div className="updates-page">
    {error && <div className="alert-strip"><AlertTriangle size={18} />{error}<button onClick={() => setError('')} aria-label="关闭"><X size={16} /></button></div>}
    <section className="update-grid">
      <article className="panel version-panel">
        <PanelHeader icon={<PackageCheck size={21} />} title="主控版本" subtitle={`发布源 ${info?.repository || 'T-Matrix/mmwx-guard'}`} />
        <div className="version-comparison"><div><small>当前版本</small><strong>{currentVersion}</strong></div><span>→</span><div><small>最新版本</small><strong>{loading ? '检查中...' : info?.latest_version || '-'}</strong></div></div>
        <div className={`update-state ${info?.status.state || 'idle'}`}><i /><span>{info?.status.message || '正在读取更新状态'}</span></div>
        <div className="update-actions">
          <button className="secondary-button" onClick={() => void check()} disabled={loading}><RefreshCw size={17} className={loading ? 'spin' : ''} />检查更新</button>
          {info?.release_url && <a className="secondary-button" href={info.release_url} target="_blank" rel="noreferrer"><ExternalLink size={17} />发布说明</a>}
          <button className="primary-button" onClick={() => setConfirmController(true)} disabled={!info?.update_available || controllerBusy}><Download size={17} />{info?.update_available ? '更新主控' : '已是最新版'}</button>
        </div>
      </article>
      <article className="panel update-note">
        <PanelHeader icon={<ShieldCheck size={21} />} title="校验与回滚" subtitle="更新器只接受固定 GitHub 仓库发布" />
        <ul><li><Check size={16} />下载大小与 SHA-256 双重校验</li><li><Check size={16} />安装前执行新版二进制版本自检</li><li><Check size={16} />主控健康检查失败自动恢复上一版</li><li><Check size={16} />Agent 未重新上线自动恢复上一版</li></ul>
      </article>
    </section>
    <section className="panel management-panel agent-update-panel">
      <div className="section-toolbar"><div><h2>Agent 版本</h2><p>只显示在线机器；版本落后时可批量更新</p></div><button className="primary-button" disabled={selected.length === 0 || agentBusy} onClick={() => void updateAgents()}><Download size={18} />{agentBusy ? '正在提交...' : `更新选中 ${selected.length} 台`}</button></div>
      <div className="table-wrap"><table><thead><tr><th className="select-cell"><input type="checkbox" aria-label="选择全部待更新 Agent" checked={candidates.length > 0 && selected.length === candidates.length} onChange={event => setSelected(event.target.checked ? candidates.map(agent => agent.id) : [])} /></th><th>服务器</th><th>状态</th><th>当前版本</th><th>目标版本</th><th>更新结果</th></tr></thead><tbody>
        {agents.filter(agent => agent.status === 'online').map(agent => { const eligible = agent.version !== currentVersion; const result = results.find(row => row.agent_id === agent.id); return <tr key={agent.id}><td className="select-cell"><input type="checkbox" aria-label={`选择 ${agent.name}`} disabled={!eligible || agentBusy} checked={selected.includes(agent.id)} onChange={event => setSelected(ids => event.target.checked ? [...ids, agent.id] : ids.filter(id => id !== agent.id))} /></td><td><strong>{agent.name}</strong><small>{agent.ip_address || '-'}</small></td><td><Status status={agent.status} protected={agent.telemetry?.protected} /></td><td className="mono">{agent.version || '-'}</td><td className="mono">{currentVersion}</td><td>{result ? <span className={result.success ? 'result-ok' : 'result-error'}>{result.success ? <Check size={16} /> : <X size={16} />}{result.message}</span> : eligible ? <span className="update-needed">可更新</span> : <span className="muted">已是最新版</span>}</td></tr> })}
        {!agents.some(agent => agent.status === 'online') && <tr><td colSpan={6}><Empty text="暂无在线 Agent" /></td></tr>}
      </tbody></table></div>
    </section>
    {confirmController && <Modal title="确认更新主控" subtitle={`${currentVersion} → ${info?.latest_version}`} onClose={() => setConfirmController(false)}><div className="confirm-update"><AlertTriangle size={24} /><p>更新会短暂重启主控，在线 Agent 会自动重连。数据库与当前防护规则不会被修改。</p><div className="dialog-actions"><button className="secondary-button" onClick={() => setConfirmController(false)}>取消</button><button className="primary-button" disabled={controllerBusy} onClick={() => void updateController()}>{controllerBusy ? '正在提交...' : '确认更新'}</button></div></div></Modal>}
  </div>
}

function EnrollmentDialog({ onClose }: { onClose: () => void }) {
  const [label, setLabel] = useState('')
  const [result, setResult] = useState<{ install_command: string; expires_in_minutes: number } | null>(null)
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true)
    try { setResult(await api('/api/admin/enrollments', { method: 'POST', body: JSON.stringify({ label, ttl_minutes: 30 }) })) } finally { setBusy(false) }
  }
  const copy = async () => { if (result) { await navigator.clipboard.writeText(result.install_command); setCopied(true); window.setTimeout(() => setCopied(false), 1500) } }
  return <Modal title="添加服务器" subtitle="在目标服务器执行一次安装命令" onClose={onClose}>
    {!result ? <form onSubmit={submit} className="form-grid"><label className="full"><span>服务器名称</span><input autoFocus value={label} onChange={e => setLabel(e.target.value)} placeholder="例如：DMIT LAX 主控" required /></label><div className="dialog-actions"><button type="button" className="secondary-button" onClick={onClose}>取消</button><button className="primary-button" disabled={busy}>{busy ? '生成中...' : '生成安装命令'}</button></div></form> : <div className="command-result"><div className="success-mark"><Check size={22} />一次性命令已生成，{result.expires_in_minutes} 分钟内有效</div><pre>{result.install_command}</pre><div className="dialog-actions"><button className="secondary-button" onClick={onClose}>关闭</button><button className="primary-button" onClick={copy}>{copied ? <Check size={18} /> : <Copy size={18} />}{copied ? '已复制' : '复制命令'}</button></div></div>}
  </Modal>
}

function RenameAgentDialog({ agent, onClose, onSaved }: { agent: Agent; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(agent.name)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true); setError('')
    try {
      await api(`/api/admin/agents/${encodeURIComponent(agent.id)}`, { method: 'PATCH', body: JSON.stringify({ name }) })
      onSaved()
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return <Modal title="修改服务器名称" subtitle={agent.ip_address || agent.id} onClose={onClose}>
    <form onSubmit={submit} className="form-grid">{error && <div className="form-error full">{error}</div>}<label className="full"><span>服务器名称</span><input autoFocus maxLength={80} value={name} onChange={e => setName(e.target.value)} required /></label><div className="dialog-actions"><button type="button" className="secondary-button" onClick={onClose}>取消</button><button className="primary-button" disabled={busy || !name.trim()}>{busy ? '保存中...' : '保存名称'}</button></div></form>
  </Modal>
}

function PolicyDialog({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState('弹性连接防护')
  const [ports, setPorts] = useState<PortRule[]>([{ port: 15542, per_ip_rate: 100, per_ip_burst: 500, aggregate_rate: 300, aggregate_burst: 1500, enabled: true }])
  const [globalRate, setGlobalRate] = useState(800)
  const [globalBurst, setGlobalBurst] = useState(4000)
  const [exemptPorts, setExemptPorts] = useState('22,48357')
  const [trusted, setTrusted] = useState('')
  const [busy, setBusy] = useState(false)
  const updatePort = (index: number, field: keyof PortRule, value: number | boolean) => setPorts(current => current.map((p, i) => i === index ? { ...p, [field]: value } : p))
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true)
    const policy = { id: 0, revision: 1, name, enabled: true, ports, global: { rate: globalRate, burst: globalBurst, exempt_ports: exemptPorts.split(',').map(Number).filter(Boolean), enabled: true }, trusted_cidrs: trusted.split(/[\s,]+/).filter(Boolean), syn_sent_timeout: 15, syn_recv_timeout: 30 }
    try { await api('/api/admin/policies', { method: 'POST', body: JSON.stringify(policy) }); onSaved() } finally { setBusy(false) }
  }
  return <Modal wide title="新建防护策略" subtitle="令牌桶允许短时突发，持续超额才会丢弃" onClose={onClose}>
    <form onSubmit={submit} className="form-grid policy-form"><label className="full"><span>策略名称</span><input value={name} onChange={e => setName(e.target.value)} required /></label>
      {ports.map((port, index) => <div className="port-editor full" key={index}><div className="editor-title"><strong>TCP 端口规则 {index + 1}</strong>{ports.length > 1 && <button type="button" onClick={() => setPorts(p => p.filter((_, i) => i !== index))}><Trash2 size={17} /></button>}</div><div className="five-cols"><NumberField label="端口" value={port.port} onChange={v => updatePort(index, 'port', v)} /><NumberField label="单IP速率 /s" value={port.per_ip_rate} onChange={v => updatePort(index, 'per_ip_rate', v)} /><NumberField label="单IP突发" value={port.per_ip_burst} onChange={v => updatePort(index, 'per_ip_burst', v)} /><NumberField label="总速率 /s" value={port.aggregate_rate} onChange={v => updatePort(index, 'aggregate_rate', v)} /><NumberField label="总突发" value={port.aggregate_burst} onChange={v => updatePort(index, 'aggregate_burst', v)} /></div></div>)}
      <button type="button" className="add-rule full" onClick={() => setPorts(p => [...p, { port: 443, per_ip_rate: 100, per_ip_burst: 500, aggregate_rate: 300, aggregate_burst: 1500, enabled: true }])}><Plus size={17} />增加端口规则</button>
      <NumberField label="整机 SYN 速率 /s" value={globalRate} onChange={setGlobalRate} /><NumberField label="整机突发额度" value={globalBurst} onChange={setGlobalBurst} /><label><span>永久排除端口</span><input value={exemptPorts} onChange={e => setExemptPorts(e.target.value)} placeholder="22,48357" /></label><label className="full"><span>可信前置 IP / CIDR</span><textarea value={trusted} onChange={e => setTrusted(e.target.value)} placeholder="每行一个，例如 212.17.236.133/32" /></label>
      <div className="dialog-actions full"><button type="button" className="secondary-button" onClick={onClose}>取消</button><button className="primary-button" disabled={busy}>{busy ? '保存中...' : '保存策略'}</button></div>
    </form>
  </Modal>
}

function DeployDialog({ policy, agents, onClose, onDone }: { policy: Policy; agents: Agent[]; onClose: () => void; onDone: () => void }) {
  const online = agents.filter(a => a.status === 'online')
  const [selected, setSelected] = useState<string[]>(online.map(a => a.id))
  const [busy, setBusy] = useState(false)
  const [results, setResults] = useState<{ agent_id: string; success: boolean; message: string }[] | null>(null)
  const deploy = async () => { setBusy(true); try { const data = await api<{ results: typeof results }>(`/api/admin/policies/${policy.id}/deploy`, { method: 'POST', body: JSON.stringify({ agent_ids: selected }) }); setResults(data.results) } finally { setBusy(false) } }
  return <Modal title="批量下发策略" subtitle={`${policy.name} · REV ${policy.revision}`} onClose={onClose}>
    {!results ? <><div className="agent-select">{agents.map(agent => <label key={agent.id} className={agent.status !== 'online' ? 'disabled' : ''}><input type="checkbox" disabled={agent.status !== 'online'} checked={selected.includes(agent.id)} onChange={e => setSelected(ids => e.target.checked ? [...ids, agent.id] : ids.filter(id => id !== agent.id))} /><span><strong>{agent.name}</strong><small>{agent.ip_address || '等待连接'}</small></span><Status status={agent.status} protected={agent.telemetry?.protected} /></label>)}</div><div className="dialog-actions"><button className="secondary-button" onClick={onClose}>取消</button><button className="primary-button" disabled={busy || selected.length === 0} onClick={deploy}>{busy ? '正在下发...' : `下发到 ${selected.length} 台`}</button></div></> : <><div className="deploy-results">{results?.map(row => <div key={row.agent_id}>{row.success ? <Check size={19} /> : <X size={19} />}<span>{agents.find(a => a.id === row.agent_id)?.name || row.agent_id}</span><small>{row.message}</small></div>)}</div><div className="dialog-actions"><button className="primary-button" onClick={onDone}>完成</button></div></>}
  </Modal>
}

function AuthScreen({ setup, onAuthenticated }: { setup: boolean; onAuthenticated: () => Promise<void> }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async (e: FormEvent) => { e.preventDefault(); setBusy(true); setError(''); try { await api(setup ? '/api/setup' : '/api/login', { method: 'POST', body: JSON.stringify({ username, password }) }); await onAuthenticated() } catch (err) { setError((err as Error).message) } finally { setBusy(false) } }
  return <div className="auth-screen login-pixel-bg"><section className="auth-window"><header className="auth-card-header"><h1>{setup ? '欢迎使用妙妙屋X安全防护' : '登录妙妙屋X安全防护'}</h1><p>{setup ? '这是首次启动，请创建管理员账号' : '请输入管理员账号以访问安全防护后台'}</p></header><form onSubmit={submit}>{error && <div className="form-error">{error}</div>}<label><span>用户名</span><input autoFocus autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} placeholder="请输入用户名" /></label><label><span>密码</span><input type="password" autoComplete={setup ? 'new-password' : 'current-password'} value={password} onChange={e => setPassword(e.target.value)} placeholder={setup ? '至少 10 位' : '请输入密码'} /></label><button className="primary-button auth-submit" disabled={busy}>{busy ? (setup ? '创建中...' : '登录中...') : setup ? '创建管理员账号' : '登录'}</button></form></section></div>
}

function Modal({ title, subtitle, onClose, children, wide = false }: { title: string; subtitle: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return <div className="modal-backdrop" role="presentation" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}><section className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={title}><header><div><h2>{title}</h2><p>{subtitle}</p></div><button className="icon-button" onClick={onClose} title="关闭" aria-label="关闭"><X size={20} /></button></header><div className="modal-body">{children}</div></section></div>
}

function Metric({ icon, title, value, detail, tone }: { icon: ReactNode; title: string; value: string; detail: string; tone: string }) { return <article className={`metric ${tone}`}><div className="metric-head"><h2>{title}</h2><span>{icon}</span></div><p>{detail}</p><strong>{value}</strong></article> }
function PanelHeader({ icon, title, subtitle }: { icon: ReactNode; title: string; subtitle: string }) { return <div className="panel-header"><span>{icon}</span><div><h2>{title}</h2><p>{subtitle}</p></div></div> }
function Empty({ text }: { text: string }) { return <div className="empty"><Clipboard size={26} /><span>{text}</span></div> }
function NumberField({ label, value, onChange }: { label: string; value: number; onChange: (v: number) => void }) { return <label><span>{label}</span><input type="number" min="1" value={value} onChange={e => onChange(Number(e.target.value))} required /></label> }
function Status({ status, protected: active }: { status: string; protected?: boolean }) { return <span className={`status ${status}`}><i />{status === 'online' ? (active ? '防护中' : '在线') : '离线'}</span> }
function StatusDot({ level }: { level: string }) { return <i className={`status-dot ${level}`} /> }
function EventLevel({ level }: { level: string }) { const labels: Record<string, string> = { info: '信息', warning: '警告', error: '失败' }; return <span className={`event-level ${level}`}>{labels[level] || level}</span> }
function LoadingScreen() { return <div className="loading-screen login-pixel-bg"><img className="loading-logo" src="/images/logo.webp" alt="妙妙屋 Logo" /><p>正在检查系统状态...</p></div> }

function aggregateSources(agents: Agent[]): SourceCount[] {
  const map = new Map<string, SourceCount>()
  agents.forEach(agent => agent.telemetry?.top_sources?.forEach(source => { const current = map.get(source.ip) || { ip: source.ip, connections: 0, dropped: 0 }; current.connections += source.connections; current.dropped = (current.dropped || 0) + (source.dropped || 0); map.set(source.ip, current) }))
  return [...map.values()].sort((a, b) => (b.connections + (b.dropped || 0)) - (a.connections + (a.dropped || 0)))
}
function formatNumber(value: number) { return new Intl.NumberFormat('zh-CN', { notation: value >= 100000 ? 'compact' : 'standard', maximumFractionDigits: 1 }).format(value) }
function percentage(used: number, total: number) { return total ? `${Math.round(used / total * 100)}%` : '-' }
function formatMemory(bytes: number) { if (!bytes) return '-'; const gibibytes = bytes / 1024 ** 3; return gibibytes >= 1 ? `${gibibytes.toFixed(gibibytes >= 10 ? 0 : 1)} GB` : `${Math.round(bytes / 1024 ** 2)} MB` }
function formatTime(value: string) { if (!value) return '-'; return new Date(value).toLocaleString('zh-CN', { hour12: false }) }
function relativeTime(value: string) { const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000)); if (seconds < 60) return `${seconds}秒前`; if (seconds < 3600) return `${Math.floor(seconds / 60)}分钟前`; if (seconds < 86400) return `${Math.floor(seconds / 3600)}小时前`; return `${Math.floor(seconds / 86400)}天前` }

export default App
