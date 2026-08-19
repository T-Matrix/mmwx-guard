import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowLeft, Check, ChevronDown, ChevronRight, CircleGauge, Clipboard, Copy,
  Cable, Cpu, Download, ExternalLink, FileClock, Filter, ListFilter, LogOut, Moon,
  Network, PackageCheck, Pencil, Plus, Radio, RefreshCw, Save, Server, Settings2,
  ShieldCheck, ShieldX, Sun, Trash2, X, Zap,
} from 'lucide-react'
import { api } from './api'
import type { Agent, EventItem, MMWNode, Policy, PortRule, SourceCount, Status as SystemStatus, UpdateInfo } from './api'

type Tab = 'overview' | 'agents' | 'events' | 'updates'
type DetailTab = 'overview' | 'protection' | 'services' | 'events'
type Summary = { agents_total: number; agents_online: number; sockets: number; established: number; time_wait: number; conntrack: number; dropped: number; protected: number }
type EditablePortRule = PortRule & { manual: boolean; source_rules: string[] }

const defaultSummary: Summary = { agents_total: 0, agents_online: 0, sockets: 0, established: 0, time_wait: 0, conntrack: 0, dropped: 0, protected: 0 }

function App() {
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [tab, setTab] = useState<Tab>('overview')
  const [summary, setSummary] = useState<Summary>(defaultSummary)
  const [agents, setAgents] = useState<Agent[]>([])
  const [events, setEvents] = useState<EventItem[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [enrollOpen, setEnrollOpen] = useState(false)
  const [renameAgent, setRenameAgent] = useState<Agent | null>(null)
  const [selectedAgentID, setSelectedAgentID] = useState('')
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
      const [nextSummary, agentResult, eventResult] = await Promise.all([
        api<Summary>('/api/admin/summary'),
        api<{ agents: Agent[] }>('/api/admin/agents'),
        api<{ events: EventItem[] }>('/api/admin/events'),
      ])
      setSummary(nextSummary)
      setAgents(agentResult.agents || [])
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

  const selectedAgent = agents.find(agent => agent.id === selectedAgentID)
  const navigate = (next: Tab) => {
    setSelectedAgentID('')
    setTab(next)
  }

  return (
    <div className="app-shell">
      <Header tab={tab} setTab={navigate} theme={theme} setTheme={setTheme} admin={status.admin} version={status.version} onLogout={logout} />
      <main className="content">
        {error && <div className="alert-strip"><AlertTriangle size={18} />{error}<button onClick={() => setError('')} aria-label="关闭"><X size={16} /></button></div>}
        {selectedAgent ? <ServerDetail agent={selectedAgent} events={events.filter(event => event.agent_id === selectedAgent.id)} onBack={() => setSelectedAgentID('')} onRename={() => setRenameAgent(selectedAgent)} onSaved={() => void refresh()} /> : <>
          {tab === 'overview' && <Overview summary={summary} agents={agents} events={events} />}
          {tab === 'agents' && <Agents agents={agents} onEnroll={() => setEnrollOpen(true)} onOpen={agent => setSelectedAgentID(agent.id)} onRename={setRenameAgent} onDelete={async id => { await api(`/api/admin/agents/${id}`, { method: 'DELETE' }); void refresh() }} />}
          {tab === 'events' && <Events events={events} agents={agents} />}
          {tab === 'updates' && <Updates currentVersion={status.version} agents={agents} onRefresh={() => void refresh(true)} />}
        </>}
      </main>
      {enrollOpen && <EnrollmentDialog onClose={() => setEnrollOpen(false)} />}
      {renameAgent && <RenameAgentDialog agent={renameAgent} onClose={() => setRenameAgent(null)} onSaved={() => { setRenameAgent(null); void refresh() }} />}
    </div>
  )
}

function Header({ tab, setTab, theme, setTheme, admin, version, onLogout }: { tab: Tab; setTab: (tab: Tab) => void; theme: string; setTheme: (theme: string) => void; admin: string; version: string; onLogout: () => void }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const items: { id: Tab; label: string; icon: typeof Activity }[] = [
    { id: 'overview', label: '安全概览', icon: Activity },
    { id: 'agents', label: '服务器管理', icon: Server },
    { id: 'events', label: '拦截记录', icon: ListFilter },
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
        <div className="user-menu" onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget as Node)) setMenuOpen(false) }}>
          <button className="admin-menu" onClick={() => setMenuOpen(open => !open)} aria-expanded={menuOpen} aria-haspopup="menu">
            <img className="avatar" src="/images/admin-avatar.webp" alt="管理员头像" /><span><strong>{admin}</strong><small>ADMIN</small></span><ChevronDown size={16} />
          </button>
          {menuOpen && <div className="user-dropdown" role="menu">
            <div className="user-summary"><img className="avatar large" src="/images/admin-avatar.webp" alt="" /><strong>{admin}</strong><small>管理员 · {version}</small></div>
            <button role="menuitem" onClick={() => { setTab('updates'); setMenuOpen(false) }}><PackageCheck size={17} /><span>版本更新</span><small>{version}</small></button>
            <button role="menuitem" onClick={() => { setTheme(theme === 'pixel' ? 'gold' : 'pixel'); setMenuOpen(false) }}><Settings2 size={17} /><span>界面风格</span><small>{theme === 'pixel' ? '妙妙屋' : '金色'}</small></button>
            <button role="menuitem" className="logout-item" onClick={onLogout}><LogOut size={17} /><span>退出登录</span></button>
          </div>}
        </div>
      </div>
    </header>
  )
}

function PageTitle({ tab, busy, onRefresh }: { tab: Tab; busy: boolean; onRefresh: () => void }) {
  const titles: Record<Tab, [string, string]> = {
    overview: ['安全概览', '所有服务器的实时连接与防护状态'],
    agents: ['服务器管理', '注册、查看并批量管理安全防护 Agent'],
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
      <Metric icon={<Network />} title="ESTABLISHED" value={formatNumber(summary.established)} detail="当前已建立 TCP 连接" tone="blue" />
      <Metric icon={<Network />} title="TIME_WAIT" value={formatNumber(summary.time_wait)} detail="等待内核回收的 TCP 连接" tone="coral" />
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
      <div className="table-wrap"><table><thead><tr><th>服务器</th><th>状态</th><th>IP 地址</th><th>负载</th><th>内存</th><th>ESTABLISHED</th><th>TIME_WAIT</th><th>拦截</th><th>策略</th></tr></thead><tbody>
        {agents.map(agent => <tr key={agent.id}><td><strong>{agent.name}</strong><small>{agent.os} / {agent.arch}</small></td><td><Status status={agent.status} protected={agent.telemetry?.protected} /></td><td className="mono">{agent.ip_address || '-'}</td><td>{agent.telemetry ? agent.telemetry.load_1.toFixed(2) : '-'}</td><td>{agent.telemetry ? percentage(agent.telemetry.memory_used, agent.telemetry.memory_total) : '-'}</td><td>{formatNumber(agent.telemetry?.sockets.established || 0)}</td><td>{formatNumber(agent.telemetry?.sockets.time_wait || 0)}</td><td className="danger-text">{formatNumber(agent.telemetry?.dropped_total || 0)}</td><td>{agent.policy_name || '未下发'}</td></tr>)}
        {agents.length === 0 && <tr><td colSpan={9}><Empty text="还没有服务器，前往服务器管理添加第一台" /></td></tr>}
      </tbody></table></div>
    </section>
  </>
}

function Agents({ agents, onEnroll, onOpen, onRename, onDelete }: { agents: Agent[]; onEnroll: () => void; onOpen: (agent: Agent) => void; onRename: (agent: Agent) => void; onDelete: (id: string) => Promise<void> }) {
  return <section className="panel management-panel">
    <div className="section-toolbar"><div><h2>服务器列表 ({agents.length})</h2><p>进入服务器详情后独立设置防护、端口与可信入口</p></div><button className="primary-button" onClick={onEnroll}><Plus size={18} />添加服务器</button></div>
    <div className="table-wrap"><table className="agent-table"><thead><tr><th>名称</th><th>连接状态</th><th>公网 IP</th><th>CPU</th><th>内存</th><th>ESTABLISHED</th><th>TIME_WAIT</th><th>SYN 堆积</th><th>Conntrack</th><th>防护</th><th>操作</th></tr></thead><tbody>
      {agents.map(agent => <tr key={agent.id}><td><button className="server-link" onClick={() => onOpen(agent)}><span><strong>{agent.name}</strong><small>Agent {agent.version || '-'}</small></span><ChevronRight size={17} /></button><IntegrationBadges agent={agent} /></td><td><Status status={agent.status} protected={agent.telemetry?.protected} /></td><td className="mono">{agent.ip_address || '-'}</td><td>{agent.telemetry?.cpu_usage == null ? '-' : `${agent.telemetry.cpu_usage.toFixed(1)}%`}</td><td className="resource-cell"><strong>{agent.telemetry ? percentage(agent.telemetry.memory_used, agent.telemetry.memory_total) : '-'}</strong><small>{agent.telemetry ? `${formatMemory(agent.telemetry.memory_used)} / ${formatMemory(agent.telemetry.memory_total)}` : '-'}</small></td><td>{formatNumber(agent.telemetry?.sockets.established || 0)}</td><td>{formatNumber(agent.telemetry?.sockets.time_wait || 0)}</td><td>{(agent.telemetry?.sockets.syn_recv || 0) + (agent.telemetry?.sockets.syn_sent || 0)}</td><td>{formatNumber(agent.telemetry?.conntrack || 0)}</td><td>{agent.policy_name ? <span className="protection-label"><ShieldCheck size={14} />{agent.policy_name}</span> : <span className="muted">未配置</span>}</td><td><div className="row-actions"><button title="防护设置" onClick={() => onOpen(agent)}><ShieldCheck size={18} /></button><button title="修改名称" onClick={() => onRename(agent)}><Pencil size={18} /></button><button title="删除" className="danger" onClick={() => void onDelete(agent.id)}><Trash2 size={18} /></button></div></td></tr>)}
      {agents.length === 0 && <tr><td colSpan={11}><Empty text="点击“添加服务器”生成一次性安装命令" /></td></tr>}
    </tbody></table></div>
  </section>
}

function ServerDetail({ agent, events, onBack, onRename, onSaved }: { agent: Agent; events: EventItem[]; onBack: () => void; onRename: () => void; onSaved: () => void }) {
  const [tab, setTab] = useState<DetailTab>('overview')
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [policyLoading, setPolicyLoading] = useState(true)
  const [policyError, setPolicyError] = useState('')
  useEffect(() => {
    let active = true
    setPolicyLoading(true)
    setPolicyError('')
    void api<{ policy: Policy | null }>(`/api/admin/agents/${encodeURIComponent(agent.id)}/protection`).then(result => { if (active) setPolicy(result.policy) }).catch(error => { if (active) setPolicyError((error as Error).message) }).finally(() => { if (active) setPolicyLoading(false) })
    return () => { active = false }
  }, [agent.id])
  const items: { id: DetailTab; label: string; icon: typeof Activity }[] = [
    { id: 'overview', label: '运行概览', icon: Activity },
    { id: 'protection', label: '防护设置', icon: ShieldCheck },
    { id: 'services', label: '服务与端口', icon: Radio },
    { id: 'events', label: '安全事件', icon: FileClock },
  ]
  return <div className="server-detail">
    <button className="back-button" onClick={onBack}><ArrowLeft size={17} />服务器管理</button>
    <header className="server-heading">
      <div><div className="server-title"><h1>{agent.name}</h1><Status status={agent.status} protected={agent.telemetry?.protected} /><button className="plain-icon" onClick={onRename} title="修改名称" aria-label="修改服务器名称"><Pencil size={17} /></button></div><p><span className="mono">{agent.ip_address || '-'}</span><i />{agent.os} / {agent.arch}<i />Agent {agent.version || '-'}</p></div>
      <div className="server-heading-stats"><span><small>当前策略</small><strong>{agent.policy_name || '未配置'}</strong></span><span><small>最后上报</small><strong>{agent.last_seen ? relativeTime(agent.last_seen) : '-'}</strong></span></div>
    </header>
    <nav className="detail-tabs" aria-label="服务器详情导航">{items.map(item => <button key={item.id} className={tab === item.id ? 'active' : ''} onClick={() => setTab(item.id)}><item.icon size={17} />{item.label}</button>)}</nav>
    {tab === 'overview' && <ServerOverview agent={agent} policy={policy} />}
    {tab === 'protection' && (policyLoading ? <div className="panel loading-panel"><RefreshCw className="spin" size={22} />正在读取服务器防护设置...</div> : policyError ? <div className="alert-strip"><AlertTriangle size={18} />{policyError}</div> : <ProtectionEditor agent={agent} initialPolicy={policy} onSaved={saved => { setPolicy(saved); onSaved() }} />)}
    {tab === 'services' && <ServicePorts agent={agent} />}
    {tab === 'events' && <Events events={events} agents={[agent]} />}
  </div>
}

function ServerOverview({ agent, policy }: { agent: Agent; policy: Policy | null }) {
  const telemetry = agent.telemetry
  const protectedPorts = policy?.ports.filter(port => port.enabled).map(port => port.port) || []
  return <>
    <section className="detail-metrics">
      <Metric icon={<Cpu />} title="CPU" value={telemetry?.cpu_usage == null ? '-' : `${telemetry.cpu_usage.toFixed(1)}%`} detail={`Load ${telemetry?.load_1.toFixed(2) || '-'}`} tone="coral" />
      <Metric icon={<CircleGauge />} title="内存" value={telemetry ? percentage(telemetry.memory_used, telemetry.memory_total) : '-'} detail={telemetry ? `${formatMemory(telemetry.memory_used)} / ${formatMemory(telemetry.memory_total)}` : '-'} tone="blue" />
      <Metric icon={<Network />} title="ESTABLISHED" value={formatNumber(telemetry?.sockets.established || 0)} detail="当前已建立 TCP 连接" tone="blue" />
      <Metric icon={<Network />} title="TIME_WAIT" value={formatNumber(telemetry?.sockets.time_wait || 0)} detail="等待内核回收" tone="amber" />
    </section>
    <section className="detail-grid">
      <article className="panel detail-panel"><PanelHeader icon={<ShieldCheck size={21} />} title="当前防护" subtitle="只作用于这台服务器" /><dl className="detail-list"><div><dt>状态</dt><dd>{telemetry?.protected ? '已启用' : '未启用'}</dd></div><div><dt>保护端口</dt><dd className="mono">{protectedPorts.join(', ') || '-'}</dd></div><div><dt>整机新连接</dt><dd>{policy?.global.enabled ? `${policy.global.rate}/s · 突发 ${policy.global.burst}` : '关闭'}</dd></div><div><dt>累计拦截</dt><dd className="danger-text">{formatNumber(telemetry?.dropped_total || 0)}</dd></div></dl></article>
      <article className="panel detail-panel"><PanelHeader icon={<Zap size={21} />} title="当前来源" subtitle="按连接数排序" />{telemetry?.top_sources?.length ? <div className="mini-source-list">{telemetry.top_sources.slice(0, 6).map(source => <div key={source.ip}><span className="mono">{source.ip}</span><strong>{formatNumber(source.connections)}</strong></div>)}</div> : <Empty text="暂无连接来源" />}</article>
    </section>
  </>
}

function ProtectionEditor({ agent, initialPolicy, onSaved }: { agent: Agent; initialPolicy: Policy | null; onSaved: (policy: Policy) => void }) {
  const discovered = discoveredPorts(agent)
  const [policy, setPolicy] = useState<Policy>(() => initialPolicy || defaultAgentPolicy(agent.name, discovered))
  const [selectedSources, setSelectedSources] = useState<string[]>(() => discovered.filter(source => (initialPolicy?.ports || []).some(port => port.port === source.port)).map(source => source.key))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  const updatePort = (index: number, field: keyof PortRule, value: number | boolean) => setPolicy(current => ({ ...current, ports: current.ports.map((port, portIndex) => portIndex === index ? { ...port, [field]: value } : port) }))
  const toggleSource = (source: DiscoveredPort, checked: boolean) => {
    setSelectedSources(current => checked ? [...new Set([...current, source.key])] : current.filter(key => key !== source.key))
    setPolicy(current => {
      if (checked) return current.ports.some(port => port.port === source.port) ? current : { ...current, ports: [...current.ports, newPortRule(source.port, false)] }
      const anotherSelected = discovered.some(item => item.port === source.port && item.key !== source.key && selectedSources.includes(item.key))
      return anotherSelected ? current : { ...current, ports: current.ports.filter(port => port.port !== source.port) }
    })
  }
  const removePort = (index: number) => {
    const port = policy.ports[index].port
    setPolicy(current => ({ ...current, ports: current.ports.filter((_, portIndex) => portIndex !== index) }))
    setSelectedSources(current => current.filter(key => discovered.find(source => source.key === key)?.port !== port))
  }
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError(''); setMessage('')
    try {
      const result = await api<{ policy: Policy; message: string }>(`/api/admin/agents/${encodeURIComponent(agent.id)}/protection`, { method: 'PUT', body: JSON.stringify(policy) })
      setPolicy(result.policy); setMessage('已保存并只应用到这台服务器'); onSaved(result.policy)
    } catch (err) { setError((err as Error).message) }
    finally { setBusy(false) }
  }
  return <form className="protection-page" onSubmit={submit}>
    {error && <div className="alert-strip"><AlertTriangle size={18} />{error}</div>}
    {message && <div className="success-strip"><Check size={18} />{message}</div>}
    <section className="settings-section">
      <div className="settings-heading"><div><h2>防护范围</h2><p>从这台机器实际发现的服务端口中选择</p></div><label className="switch-field"><input type="checkbox" checked={policy.enabled} onChange={event => setPolicy(current => ({ ...current, enabled: event.target.checked }))} /><span>启用防护</span></label></div>
      <div className="discovered-list">{discovered.map(source => <label key={source.key} className={!source.tcp ? 'disabled' : ''}><input type="checkbox" disabled={!source.tcp} checked={selectedSources.includes(source.key)} onChange={event => toggleSource(source, event.target.checked)} /><span className={`service-mark ${source.kind}`}><source.icon size={18} /></span><span className="discovered-main"><strong>{source.title}</strong><small className="mono">{source.detail}</small></span><span className={`rule-state ${source.active ? 'active' : ''}`}>{source.active ? '运行中' : '已配置，未运行'}</span></label>)}{discovered.length === 0 && <Empty text="尚未发现妙妙屋节点或 ForwardX 入口，可在下方手工添加端口" />}</div>
    </section>
    <section className="settings-section">
      <div className="settings-heading"><div><h2>端口阈值</h2><p>超过弹性额度时只丢弃新的 TCP 握手</p></div></div>
      <div className="port-settings">{policy.ports.map((port, index) => <div className="port-editor" key={`${port.port}-${index}`}><div className="editor-title"><strong>TCP :{port.port}</strong><button type="button" onClick={() => removePort(index)} title="删除端口规则" aria-label={`删除端口 ${port.port} 规则`}><Trash2 size={17} /></button></div><div className="five-cols"><NumberField label="端口" value={port.port} onChange={value => updatePort(index, 'port', value)} /><NumberField label="单 IP 速率 /s" value={port.per_ip_rate} onChange={value => updatePort(index, 'per_ip_rate', value)} /><NumberField label="单 IP 突发" value={port.per_ip_burst} onChange={value => updatePort(index, 'per_ip_burst', value)} /><NumberField label="端口总速率 /s" value={port.aggregate_rate} onChange={value => updatePort(index, 'aggregate_rate', value)} /><NumberField label="端口总突发" value={port.aggregate_burst} onChange={value => updatePort(index, 'aggregate_burst', value)} /></div></div>)}
        <button type="button" className="add-rule" onClick={() => setPolicy(current => ({ ...current, ports: [...current.ports, newPortRule(443, true)] }))}><Plus size={17} />增加手工端口</button>
      </div>
    </section>
    <section className="settings-section">
      <div className="settings-heading"><div><h2>整机与可信入口</h2><p>可信前置地址不受速率限制，管理端口始终排除</p></div><label className="switch-field"><input type="checkbox" checked={policy.global.enabled} onChange={event => setPolicy(current => ({ ...current, global: { ...current.global, enabled: event.target.checked } }))} /><span>整机规则</span></label></div>
      <div className="form-grid settings-fields"><label><span>策略名称</span><input value={policy.name} maxLength={80} onChange={event => setPolicy(current => ({ ...current, name: event.target.value }))} required /></label><NumberField label="整机 SYN 速率 /s" value={policy.global.rate} onChange={value => setPolicy(current => ({ ...current, global: { ...current.global, rate: value } }))} /><NumberField label="整机突发额度" value={policy.global.burst} onChange={value => setPolicy(current => ({ ...current, global: { ...current.global, burst: value } }))} /><label><span>永久排除端口</span><input value={policy.global.exempt_ports.join(',')} onChange={event => setPolicy(current => ({ ...current, global: { ...current.global, exempt_ports: event.target.value.split(',').map(Number).filter(Boolean) } }))} placeholder="22,48357" /></label><label className="full"><span>可信前置 IP / CIDR</span><textarea value={policy.trusted_cidrs.join('\n')} onChange={event => setPolicy(current => ({ ...current, trusted_cidrs: event.target.value.split(/[\s,]+/).filter(Boolean) }))} placeholder="每行一个，例如 212.17.236.133/32" /></label></div>
    </section>
    <div className="settings-actions"><span>{agent.status === 'online' ? '保存后立即应用到当前服务器' : '服务器离线，暂时无法应用'}</span><button className="primary-button" disabled={busy || agent.status !== 'online'}><Save size={18} />{busy ? '正在应用...' : '保存并应用'}</button></div>
  </form>
}

function ServicePorts({ agent }: { agent: Agent }) {
  const mmw = agent.telemetry?.integrations?.mmw
  const forwardx = agent.telemetry?.integrations?.forwardx
  return <div className="service-sections">
    <section className="panel service-panel"><PanelHeader icon={<Server size={21} />} title="妙妙屋节点端口" subtitle={mmw ? `Agent ${mmw.active ? '运行中' : '未运行'} · ${mmw.nodes?.length || 0} 个节点入站` : '未发现妙妙屋 Agent'} />
      <div className="table-wrap"><table><thead><tr><th>节点标签</th><th>协议</th><th>传输</th><th>安全层</th><th>监听</th><th>状态</th></tr></thead><tbody>{mmw?.nodes?.map(node => <tr key={`${node.tag}-${node.port}`}><td><strong>{node.tag || `节点 ${node.port}`}</strong></td><td>{node.protocol.toUpperCase()}</td><td>{(node.network || 'tcp').toUpperCase()}</td><td>{node.security?.toUpperCase() || '-'}</td><td className="mono">{formatListen(node.listen, node.port)}</td><td><span className={`rule-state ${node.active ? 'active' : ''}`}>{node.active ? '运行中' : '已配置，未运行'}</span></td></tr>)}{!mmw?.nodes?.length && <tr><td colSpan={6}><Empty text="未发现妙妙屋 Xray 节点入站" /></td></tr>}</tbody></table></div>
    </section>
    <section className="panel service-panel"><PanelHeader icon={<Cable size={21} />} title="ForwardX 转发规则" subtitle={forwardx ? `Agent ${forwardx.active ? '运行中' : '未运行'} · ${forwardx.rules.length} 条规则` : '未发现 ForwardX Agent'} />
      <div className="table-wrap"><table><thead><tr><th>规则</th><th>协议</th><th>入口</th><th>目标</th><th>状态</th></tr></thead><tbody>{forwardx?.rules.map(rule => <tr key={rule.id}><td><strong>{rule.id}</strong></td><td>{rule.protocol.toUpperCase()}</td><td className="mono">{rule.listen}</td><td className="mono">{rule.remote}</td><td><span className={`rule-state ${rule.active ? 'active' : ''}`}>{rule.active ? '运行中' : '未运行'}</span></td></tr>)}{!forwardx?.rules.length && <tr><td colSpan={5}><Empty text="未发现 ForwardX 转发规则" /></td></tr>}</tbody></table></div>
    </section>
  </div>
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

function PolicyDialog({ agents, onClose, onSaved }: { agents: Agent[]; onClose: () => void; onSaved: () => void }) {
  const forwardAgents = agents.filter(agent => (agent.telemetry?.integrations?.forwardx?.rules.length || 0) > 0)
  const initialAgent = forwardAgents.find(agent => agent.status === 'online' && agent.telemetry?.integrations?.forwardx?.active) || forwardAgents[0]
  const initialRules = initialAgent?.telemetry?.integrations?.forwardx?.rules.filter(rule => rule.active && supportsTCP(rule.protocol)) || []
  const [name, setName] = useState('弹性连接防护')
  const [sourceAgentID, setSourceAgentID] = useState(initialAgent?.id || '')
  const [selectedRules, setSelectedRules] = useState<string[]>(() => initialRules.map(rule => forwardRuleKey(initialAgent.id, rule.id)))
  const [ports, setPorts] = useState<EditablePortRule[]>(() => {
    if (forwardAgents.length === 0) return [newPortRule(15542, true)]
    const grouped = new Map<number, EditablePortRule>()
    initialRules.forEach(rule => {
      const key = forwardRuleKey(initialAgent.id, rule.id)
      const existing = grouped.get(rule.listen_port)
      if (existing) existing.source_rules.push(key)
      else grouped.set(rule.listen_port, { ...newPortRule(rule.listen_port, false), source_rules: [key] })
    })
    return [...grouped.values()]
  })
  const [globalRate, setGlobalRate] = useState(800)
  const [globalBurst, setGlobalBurst] = useState(4000)
  const [exemptPorts, setExemptPorts] = useState('22,48357')
  const [trusted, setTrusted] = useState('')
  const [busy, setBusy] = useState(false)
  const updatePort = (index: number, field: keyof PortRule, value: number | boolean) => setPorts(current => current.map((p, i) => i === index ? { ...p, [field]: value } : p))
  const sourceAgent = forwardAgents.find(agent => agent.id === sourceAgentID)
  const sourceRules = sourceAgent?.telemetry?.integrations?.forwardx?.rules || []
  const toggleForwardRule = (ruleID: string, listenPort: number, checked: boolean) => {
    const key = forwardRuleKey(sourceAgentID, ruleID)
    setSelectedRules(current => checked ? [...new Set([...current, key])] : current.filter(value => value !== key))
    setPorts(current => {
      if (checked) {
        const found = current.findIndex(rule => rule.port === listenPort)
        if (found < 0) return [...current, { ...newPortRule(listenPort, false), source_rules: [key] }]
        return current.map((rule, index) => index === found ? { ...rule, source_rules: [...new Set([...rule.source_rules, key])] } : rule)
      }
      return current.flatMap(rule => {
        if (!rule.source_rules.includes(key)) return [rule]
        const sourceRules = rule.source_rules.filter(value => value !== key)
        return rule.manual || sourceRules.length > 0 ? [{ ...rule, source_rules: sourceRules }] : []
      })
    })
  }
  const removePort = (index: number) => {
    const removed = ports[index]
    setSelectedRules(current => current.filter(key => !removed.source_rules.includes(key)))
    setPorts(current => current.filter((_, portIndex) => portIndex !== index))
  }
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setBusy(true)
    const cleanPorts: PortRule[] = ports.map(({ manual: _manual, source_rules: _sourceRules, ...rule }) => rule)
    const policy = { id: 0, revision: 1, name, enabled: true, ports: cleanPorts, global: { rate: globalRate, burst: globalBurst, exempt_ports: exemptPorts.split(',').map(Number).filter(Boolean), enabled: true }, trusted_cidrs: trusted.split(/[\s,]+/).filter(Boolean), syn_sent_timeout: 15, syn_recv_timeout: 30 }
    try { await api('/api/admin/policies', { method: 'POST', body: JSON.stringify(policy) }); onSaved() } finally { setBusy(false) }
  }
  return <Modal wide title="新建防护策略" subtitle="令牌桶允许短时突发，持续超额才会丢弃" onClose={onClose}>
    <form onSubmit={submit} className="form-grid policy-form"><label className="full"><span>策略名称</span><input value={name} onChange={e => setName(e.target.value)} required /></label>
      {forwardAgents.length > 0 && <section className="integration-picker full">
        <div className="integration-picker-head"><div><strong><Cable size={18} />ForwardX 转发规则</strong><small>已勾选的 TCP 入口会加入下方端口规则</small></div><label><span>来源服务器</span><select value={sourceAgentID} onChange={e => setSourceAgentID(e.target.value)}>{forwardAgents.map(agent => <option key={agent.id} value={agent.id}>{agent.name} ({agent.telemetry?.integrations?.forwardx?.rules.length || 0} 条)</option>)}</select></label></div>
        <div className="forward-rule-list">{sourceRules.map(rule => {
          const tcp = supportsTCP(rule.protocol)
          const key = forwardRuleKey(sourceAgentID, rule.id)
          return <label key={rule.id} className={!tcp ? 'disabled' : ''} title={!tcp ? 'UDP 不经过 TCP SYN 防护' : `${rule.listen} -> ${rule.remote}`}><input type="checkbox" disabled={!tcp} checked={selectedRules.includes(key)} onChange={e => toggleForwardRule(rule.id, rule.listen_port, e.target.checked)} /><span className="forward-rule-main"><strong><i>{rule.protocol.toUpperCase()}</i>{rule.listen}</strong><small>转发至 {rule.remote}</small></span><span className={`rule-state ${rule.active ? 'active' : ''}`}>{rule.active ? '运行中' : '未运行'}</span></label>
        })}</div>
      </section>}
      {ports.map((port, index) => <div className="port-editor full" key={`${port.port}-${index}`}><div className="editor-title"><strong>TCP 端口规则 {index + 1}{port.source_rules.length > 0 && <small>ForwardX</small>}</strong><button type="button" onClick={() => removePort(index)} title="删除端口规则" aria-label={`删除端口 ${port.port} 规则`}><Trash2 size={17} /></button></div><div className="five-cols"><NumberField label="端口" value={port.port} onChange={v => updatePort(index, 'port', v)} disabled={port.source_rules.length > 0} /><NumberField label="单IP速率 /s" value={port.per_ip_rate} onChange={v => updatePort(index, 'per_ip_rate', v)} /><NumberField label="单IP突发" value={port.per_ip_burst} onChange={v => updatePort(index, 'per_ip_burst', v)} /><NumberField label="总速率 /s" value={port.aggregate_rate} onChange={v => updatePort(index, 'aggregate_rate', v)} /><NumberField label="总突发" value={port.aggregate_burst} onChange={v => updatePort(index, 'aggregate_burst', v)} /></div></div>)}
      <button type="button" className="add-rule full" onClick={() => setPorts(p => [...p, newPortRule(443, true)])}><Plus size={17} />增加手工端口规则</button>
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
function NumberField({ label, value, onChange, disabled = false }: { label: string; value: number; onChange: (v: number) => void; disabled?: boolean }) { return <label><span>{label}</span><input type="number" min="1" value={value} onChange={e => onChange(Number(e.target.value))} disabled={disabled} required /></label> }
function Status({ status, protected: active }: { status: string; protected?: boolean }) { return <span className={`status ${status}`}><i />{status === 'online' ? (active ? '防护中' : '在线') : '离线'}</span> }
function IntegrationBadges({ agent }: { agent: Agent }) {
  const integrations = agent.telemetry?.integrations
  if (!integrations?.mmw && !integrations?.forwardx) return null
  return <div className="integration-badges">
    {integrations.mmw && <span className={integrations.mmw.active ? 'active' : ''} title={`${integrations.mmw.active ? '运行中' : '已发现但未运行'}${integrations.mmw.master_url ? ` · ${integrations.mmw.master_url}` : ''}`}><Server size={12} />妙妙屋 {integrations.mmw.nodes?.length || 0} 端口</span>}
    {integrations.forwardx && <span className={integrations.forwardx.active ? 'active' : ''} title={`${integrations.forwardx.active ? '运行中' : '已发现但未运行'}${integrations.forwardx.panel_url ? ` · ${integrations.forwardx.panel_url}` : ''}`}><Cable size={12} />ForwardX {integrations.forwardx.rules.length} 条</span>}
  </div>
}
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
function supportsTCP(protocol: string) { return protocol.toLowerCase() === 'tcp' || protocol.toLowerCase() === 'tcp+udp' }
function forwardRuleKey(agentID: string, ruleID: string) { return `${agentID}:${ruleID}` }
function newPortRule(port: number, manual: boolean): EditablePortRule { return { port, per_ip_rate: 100, per_ip_burst: 500, aggregate_rate: 300, aggregate_burst: 1500, enabled: true, manual, source_rules: [] } }

type DiscoveredPort = { key: string; kind: 'mmw' | 'forwardx'; title: string; detail: string; port: number; active: boolean; tcp: boolean; icon: typeof Server }
function discoveredPorts(agent: Agent): DiscoveredPort[] {
  const mmw = agent.telemetry?.integrations?.mmw?.nodes || []
  const forwardx = agent.telemetry?.integrations?.forwardx?.rules || []
  return [
    ...mmw.map((node: MMWNode) => ({ key: `mmw:${node.tag || node.port}`, kind: 'mmw' as const, title: `妙妙屋 · ${node.protocol.toUpperCase()} :${node.port}`, detail: [node.network || 'tcp', node.security].filter(Boolean).join(' / '), port: node.port, active: node.active, tcp: nodeNetworkUsesTCP(node.network || 'tcp'), icon: Server })),
    ...forwardx.map(rule => ({ key: `forwardx:${rule.id}`, kind: 'forwardx' as const, title: `ForwardX · ${rule.protocol.toUpperCase()} :${rule.listen_port}`, detail: `${rule.listen} -> ${rule.remote}`, port: rule.listen_port, active: rule.active, tcp: supportsTCP(rule.protocol), icon: Cable })),
  ].sort((left, right) => left.port - right.port)
}
function nodeNetworkUsesTCP(network: string) { return !['kcp', 'mkcp', 'quic'].includes(network.toLowerCase()) }
function defaultAgentPolicy(name: string, sources: DiscoveredPort[]): Policy {
  const ports = [...new Set(sources.filter(source => source.tcp).map(source => source.port))].map(port => newPortRule(port, false))
  return { id: 0, revision: 1, name: `${name} 防护`, enabled: true, ports, global: { rate: 800, burst: 4000, exempt_ports: [22, 48357], enabled: true }, trusted_cidrs: [], syn_sent_timeout: 15, syn_recv_timeout: 30 }
}
function formatListen(listen: string | undefined, port: number) { return `${listen || '0.0.0.0'}:${port}` }

export default App
