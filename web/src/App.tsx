import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowLeft, Check, ChevronDown, ChevronRight, CircleGauge, Clipboard, Copy,
  Cable, Cpu, Download, ExternalLink, FileClock, Filter, KeyRound, Link2, Link2Off, ListFilter, LockKeyhole, LogOut, Moon,
  Network, PackageCheck, Pencil, Plus, Radio, RefreshCw, RotateCw, Save, Search, Server, Settings2,
  ShieldCheck, ShieldX, SlidersHorizontal, Sun, Trash2, X, Zap,
} from 'lucide-react'
import { api } from './api'
import type { Agent, EventItem, MMWNode, Policy, PortRule, SourceCount, Status as SystemStatus, UpdateInfo } from './api'

type Tab = 'overview' | 'agents' | 'events' | 'updates'
type DetailTab = 'overview' | 'protection' | 'services' | 'security' | 'events'
type RouteState = { tab: Tab; agentID: string; detailTab: DetailTab }
type Summary = { agents_total: number; agents_online: number; sockets: number; established: number; time_wait: number; conntrack: number; dropped: number; protected: number }
type EditablePortRule = PortRule & { manual: boolean; source_rules: string[] }

const defaultSummary: Summary = { agents_total: 0, agents_online: 0, sockets: 0, established: 0, time_wait: 0, conntrack: 0, dropped: 0, protected: 0 }

function App() {
  const initialRoute = useMemo(readRoute, [])
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [tab, setTab] = useState<Tab>(initialRoute.tab)
  const [summary, setSummary] = useState<Summary>(defaultSummary)
  const [agents, setAgents] = useState<Agent[]>([])
  const [events, setEvents] = useState<EventItem[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [enrollOpen, setEnrollOpen] = useState(false)
  const [renameAgent, setRenameAgent] = useState<Agent | null>(null)
  const [selectedAgentID, setSelectedAgentID] = useState(initialRoute.agentID)
  const [detailTab, setDetailTab] = useState<DetailTab>(initialRoute.detailTab)
  const [deleteAgent, setDeleteAgent] = useState<Agent | null>(null)
  const [deleteBusy, setDeleteBusy] = useState(false)
  const [logoutOpen, setLogoutOpen] = useState(false)
	const [passwordOpen, setPasswordOpen] = useState(false)
  const [updateAvailable, setUpdateAvailable] = useState(false)
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
    const onPopState = () => {
      const route = readRoute()
      setTab(route.tab)
      setSelectedAgentID(route.agentID)
      setDetailTab(route.detailTab)
    }
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])
  useEffect(() => {
    if (!status?.authenticated) return
    void refresh()
    const timer = window.setInterval(() => void refresh(true), 5000)
    return () => window.clearInterval(timer)
  }, [status?.authenticated, refresh])
  useEffect(() => {
    if (!status?.authenticated) return
    void api<UpdateInfo>('/api/admin/update').then(info => setUpdateAvailable(info.update_available)).catch(() => undefined)
  }, [status?.authenticated])

  if (!status) return <LoadingScreen />
  if (!status.setup || !status.authenticated) {
    return <AuthScreen setup={!status.setup} turnstileSiteKey={status.turnstile_enabled ? status.turnstile_site_key || '' : ''} onAuthenticated={loadStatus} />
  }

  const logout = async () => {
    await api('/api/logout', { method: 'POST', body: '{}' })
    setStatus({ ...status, authenticated: false, admin: '' })
  }

  const selectedAgent = agents.find(agent => agent.id === selectedAgentID)
  const navigate = (next: RouteState) => {
    setTab(next.tab)
    setSelectedAgentID(next.agentID)
    setDetailTab(next.detailTab)
    writeRoute(next)
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">跳到主要内容</a>
      <Header tab={tab} setTab={next => navigate({ tab: next, agentID: '', detailTab: 'overview' })} theme={theme} setTheme={setTheme} admin={status.admin} version={status.version} updateAvailable={updateAvailable} onPassword={() => setPasswordOpen(true)} onLogout={() => setLogoutOpen(true)} />
      <main className="content" id="main-content">
        {error && <div className="alert-strip"><AlertTriangle size={18} />{error}<button onClick={() => setError('')} aria-label="关闭"><X size={16} /></button></div>}
        {selectedAgent ? <ServerDetail agent={selectedAgent} tab={detailTab} setTab={next => navigate({ tab: 'agents', agentID: selectedAgent.id, detailTab: next })} events={events.filter(event => event.agent_id === selectedAgent.id)} onBack={() => navigate({ tab: 'agents', agentID: '', detailTab: 'overview' })} onRename={() => setRenameAgent(selectedAgent)} onSaved={() => void refresh()} /> : <>
          <PageTitle tab={tab} busy={busy} onRefresh={() => void refresh()} />
          {tab === 'overview' && <Overview summary={summary} agents={agents} events={events} />}
          {tab === 'agents' && <Agents agents={agents} onEnroll={() => setEnrollOpen(true)} onOpen={agent => navigate({ tab: 'agents', agentID: agent.id, detailTab: 'overview' })} onRename={setRenameAgent} onDelete={setDeleteAgent} />}
          {tab === 'events' && <Events events={events} agents={agents} />}
          {tab === 'updates' && <Updates currentVersion={status.version} agents={agents} onRefresh={() => void refresh(true)} />}
        </>}
      </main>
      {enrollOpen && <EnrollmentDialog onClose={() => setEnrollOpen(false)} />}
      {renameAgent && <RenameAgentDialog agent={renameAgent} onClose={() => setRenameAgent(null)} onSaved={() => { setRenameAgent(null); void refresh() }} />}
      {deleteAgent && <ConfirmDialog title="删除服务器记录" description={`确定删除“${deleteAgent.name}”吗？在线 Agent 需要先停止，已有防护规则不会自动从服务器移除。`} confirmLabel="删除记录" busy={deleteBusy} danger onClose={() => setDeleteAgent(null)} onConfirm={async () => {
        setDeleteBusy(true)
        try { await api(`/api/admin/agents/${encodeURIComponent(deleteAgent.id)}`, { method: 'DELETE' }); setDeleteAgent(null); await refresh() }
        catch (err) { setError((err as Error).message) }
        finally { setDeleteBusy(false) }
      }} />}
	      {logoutOpen && <ConfirmDialog title="退出登录" description="确定退出当前管理员会话吗？" confirmLabel="退出登录" returnFocus=".admin-menu" onClose={() => setLogoutOpen(false)} onConfirm={async () => { await logout(); setLogoutOpen(false) }} />}
		{passwordOpen && <PasswordDialog onClose={() => setPasswordOpen(false)} />}
    </div>
  )
}

function Header({ tab, setTab, theme, setTheme, admin, version, updateAvailable, onPassword, onLogout }: { tab: Tab; setTab: (tab: Tab) => void; theme: string; setTheme: (theme: string) => void; admin: string; version: string; updateAvailable: boolean; onPassword: () => void; onLogout: () => void }) {
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
            <button role="menuitem" onClick={() => { setTab('updates'); setMenuOpen(false) }}><PackageCheck size={17} /><span>版本更新{updateAvailable && <i className="update-dot" aria-label="有新版本" />}</span><small>{version}</small></button>
            <button role="menuitem" onClick={() => { setTheme(theme === 'pixel' ? 'gold' : 'pixel'); setMenuOpen(false) }}><Settings2 size={17} /><span>界面风格</span><small>{theme === 'pixel' ? '妙妙屋' : '金色'}</small></button>
				<button role="menuitem" onClick={event => { (event.currentTarget.closest('.user-menu')?.querySelector('.admin-menu') as HTMLButtonElement | null)?.focus(); setMenuOpen(false); onPassword() }}><KeyRound size={17} /><span>修改密码</span><small>退出其他会话</small></button>
			<button role="menuitem" className="logout-item" onClick={event => { (event.currentTarget.closest('.user-menu')?.querySelector('.admin-menu') as HTMLButtonElement | null)?.focus(); setMenuOpen(false); onLogout() }}><LogOut size={17} /><span>退出登录</span></button>
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
		{agents.map(agent => <tr key={agent.id}><td><strong>{agent.name}</strong><small>{agent.os} / {agent.arch}</small></td><td><AgentStatus agent={agent} /></td><td className="mono">{agent.ip_address || '-'}</td><td>{agent.telemetry ? agent.telemetry.load_1.toFixed(2) : '-'}</td><td>{agent.telemetry ? percentage(agent.telemetry.memory_used, agent.telemetry.memory_total) : '-'}</td><td>{formatNumber(agent.telemetry?.sockets.established || 0)}</td><td>{formatNumber(agent.telemetry?.sockets.time_wait || 0)}</td><td className="danger-text">{formatNumber(agent.telemetry?.dropped_total || 0)}</td><td>{agent.policy_name || '未下发'}</td></tr>)}
        {agents.length === 0 && <tr><td colSpan={9}><Empty text="还没有服务器，前往服务器管理添加第一台" /></td></tr>}
      </tbody></table></div>
    </section>
  </>
}

function Agents({ agents, onEnroll, onOpen, onRename, onDelete }: { agents: Agent[]; onEnroll: () => void; onOpen: (agent: Agent) => void; onRename: (agent: Agent) => void; onDelete: (agent: Agent) => void }) {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const [sort, setSort] = useState('name')
  const visibleAgents = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return agents.filter(agent => {
      const matchesQuery = !needle || [agent.name, agent.ip_address, agent.os, agent.version].some(value => value?.toLowerCase().includes(needle))
      const protectedAgent = Boolean(agent.telemetry?.protected || agent.policy_name)
			const matchesFilter = filter === 'all' || filter === agent.status || (filter === 'protected' && protectedAgent) || (filter === 'unprotected' && !protectedAgent) || (filter === 'attention' && agentNeedsAttention(agent)) || (filter === 'revoked' && agent.credential_state === 'revoked')
      return matchesQuery && matchesFilter
    }).sort((left, right) => {
      if (sort === 'connections') return (right.telemetry?.sockets.established || 0) - (left.telemetry?.sockets.established || 0)
      if (sort === 'cpu') return (right.telemetry?.cpu_usage || 0) - (left.telemetry?.cpu_usage || 0)
      return left.name.localeCompare(right.name, 'zh-CN')
    })
  }, [agents, filter, query, sort])
  return <section className="panel management-panel">
    <div className="section-toolbar"><div><h2>服务器列表 ({visibleAgents.length} / {agents.length})</h2><p>进入服务器详情后独立设置防护、端口与可信入口</p></div><button className="primary-button" onClick={onEnroll}><Plus size={18} />添加服务器</button></div>
		<div className="list-controls" role="search"><label className="search-field"><Search size={17} /><span className="sr-only">搜索服务器</span><input value={query} onChange={event => setQuery(event.target.value)} placeholder="搜索名称、IP、系统或版本" /></label><label><SlidersHorizontal size={17} /><span className="sr-only">筛选状态</span><select value={filter} onChange={event => setFilter(event.target.value)}><option value="all">全部状态</option><option value="attention">需要处理</option><option value="online">在线</option><option value="offline">离线</option><option value="revoked">凭据已撤销</option><option value="protected">已配置防护</option><option value="unprotected">未配置防护</option></select></label><label><span className="sr-only">排序方式</span><select value={sort} onChange={event => setSort(event.target.value)}><option value="name">按名称排序</option><option value="connections">按连接数排序</option><option value="cpu">按 CPU 排序</option></select></label></div>
    <div className="table-wrap"><table className="agent-table"><thead><tr><th>名称</th><th>连接状态</th><th>公网 IP</th><th>CPU</th><th>内存</th><th>ESTABLISHED</th><th>TIME_WAIT</th><th>SYN 堆积</th><th>Conntrack</th><th>防护</th><th>操作</th></tr></thead><tbody>
		{visibleAgents.map(agent => <tr key={agent.id}><td><button className="server-link" onClick={() => onOpen(agent)}><span><strong>{agent.name}</strong><small>Agent {agent.version || '-'}</small></span><ChevronRight size={17} /></button><IntegrationBadges agent={agent} /></td><td><AgentStatus agent={agent} /></td><td className="mono">{agent.ip_address || '-'}</td><td>{agent.telemetry?.cpu_usage == null ? '-' : `${agent.telemetry.cpu_usage.toFixed(1)}%`}</td><td className="resource-cell"><strong>{agent.telemetry ? percentage(agent.telemetry.memory_used, agent.telemetry.memory_total) : '-'}</strong><small>{agent.telemetry ? `${formatMemory(agent.telemetry.memory_used)} / ${formatMemory(agent.telemetry.memory_total)}` : '-'}</small></td><td>{formatNumber(agent.telemetry?.sockets.established || 0)}</td><td>{formatNumber(agent.telemetry?.sockets.time_wait || 0)}</td><td>{(agent.telemetry?.sockets.syn_recv || 0) + (agent.telemetry?.sockets.syn_sent || 0)}</td><td>{formatNumber(agent.telemetry?.conntrack || 0)}</td><td>{agent.policy_name ? <span className="protection-label"><ShieldCheck size={14} />{agent.policy_name}</span> : <span className="muted">未配置</span>}</td><td><div className="row-actions"><button title="防护设置" aria-label={`打开 ${agent.name} 防护设置`} onClick={() => onOpen(agent)}><ShieldCheck size={18} /></button><button title="修改名称" aria-label={`修改 ${agent.name} 名称`} onClick={() => onRename(agent)}><Pencil size={18} /></button><button title="删除" aria-label={`删除 ${agent.name}`} className="danger" onClick={() => onDelete(agent)}><Trash2 size={18} /></button></div></td></tr>)}
      {visibleAgents.length === 0 && <tr><td colSpan={11}><Empty text={agents.length === 0 ? '点击“添加服务器”生成一次性安装命令' : '没有符合筛选条件的服务器'} /></td></tr>}
    </tbody></table></div>
  </section>
}

function ServerDetail({ agent, tab, setTab, events, onBack, onRename, onSaved }: { agent: Agent; tab: DetailTab; setTab: (tab: DetailTab) => void; events: EventItem[]; onBack: () => void; onRename: () => void; onSaved: () => void }) {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [policyLoading, setPolicyLoading] = useState(true)
  const [policyError, setPolicyError] = useState('')
  const [policyDirty, setPolicyDirty] = useState(false)
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
		{ id: 'security', label: '连接安全', icon: LockKeyhole },
		{ id: 'events', label: '安全事件', icon: FileClock },
  ]
  const canLeaveProtection = () => !policyDirty || window.confirm('防护设置还有未保存的修改，确定离开吗？')
  return <div className="server-detail">
    <button className="back-button" onClick={() => { if (canLeaveProtection()) onBack() }}><ArrowLeft size={17} />服务器管理</button>
    <header className="server-heading">
		<div><div className="server-title"><h1>{agent.name}</h1><AgentStatus agent={agent} /><button className="plain-icon" onClick={onRename} title="修改名称" aria-label="修改服务器名称"><Pencil size={17} /></button></div><p><span className="mono">{agent.ip_address || '-'}</span><i />{agent.os} / {agent.arch}<i />Agent {agent.version || '-'}</p></div>
      <div className="server-heading-stats"><span><small>当前策略</small><strong>{agent.policy_name || '未配置'}</strong></span><span><small>最后上报</small><strong>{agent.last_seen ? relativeTime(agent.last_seen) : '-'}</strong></span></div>
    </header>
    <nav className="detail-tabs" aria-label="服务器详情导航">{items.map(item => <button key={item.id} className={tab === item.id ? 'active' : ''} onClick={() => { if (item.id === tab || canLeaveProtection()) setTab(item.id) }}><item.icon size={17} />{item.label}{item.id === 'protection' && policyDirty && <i className="dirty-dot" aria-label="有未保存修改" />}</button>)}</nav>
    {tab === 'overview' && <ServerOverview agent={agent} policy={policy} />}
    {tab === 'protection' && (policyLoading ? <div className="panel loading-panel"><RefreshCw className="spin" size={22} />正在读取服务器防护设置...</div> : policyError ? <div className="alert-strip"><AlertTriangle size={18} />{policyError}</div> : <ProtectionEditor agent={agent} initialPolicy={policy} onDirtyChange={setPolicyDirty} onSaved={saved => { setPolicy(saved); onSaved() }} />)}
	{tab === 'services' && <ServicePorts agent={agent} />}
	{tab === 'security' && <AgentSecurity agent={agent} onChanged={onSaved} />}
	{tab === 'events' && <Events events={events} agents={[agent]} />}
  </div>
}

function AgentSecurity({ agent, onChanged }: { agent: Agent; onChanged: () => void }) {
	const [rotateOpen, setRotateOpen] = useState(false)
	const [revokeOpen, setRevokeOpen] = useState(false)
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState('')
	const [message, setMessage] = useState('')
	const [rotationBaseline, setRotationBaseline] = useState<string | null>(null)
	const [pairing, setPairing] = useState<{ install_command: string; expires_in_minutes: number } | null>(null)
	const [copied, setCopied] = useState(false)
	useEffect(() => {
		if (rotationBaseline === null || !agent.credential_rotated_at || agent.credential_rotated_at === rotationBaseline) return
		if (agent.status === 'online' && agent.secure_channel && agent.credential_state === 'active') {
			setMessage('凭据轮换完成，Agent 已通过新凭据安全重连')
			setRotationBaseline(null)
		}
	}, [agent.credential_rotated_at, agent.credential_state, agent.secure_channel, agent.status, rotationBaseline])
	const rotate = async () => {
		setBusy(true); setError(''); setMessage('')
		setRotationBaseline(agent.credential_rotated_at || '')
		try {
			const result = await api<{ message: string }>(`/api/admin/agents/${encodeURIComponent(agent.id)}/credentials/rotate`, { method: 'POST', body: '{}' })
			setMessage(result.message); setRotateOpen(false); window.setTimeout(onChanged, 1800)
		} catch (err) { setRotationBaseline(null); setError((err as Error).message); setRotateOpen(false) }
		finally { setBusy(false) }
	}
	const revoke = async () => {
		setBusy(true); setError(''); setMessage('')
		try {
			await api(`/api/admin/agents/${encodeURIComponent(agent.id)}/credentials/revoke`, { method: 'POST', body: '{}' })
			setMessage('Agent 凭据已撤销'); setRevokeOpen(false); onChanged()
		} catch (err) { setError((err as Error).message); setRevokeOpen(false) }
		finally { setBusy(false) }
	}
	const createPairing = async () => {
		setBusy(true); setError(''); setMessage(''); setPairing(null)
		try { setPairing(await api(`/api/admin/agents/${encodeURIComponent(agent.id)}/pairing`, { method: 'POST', body: JSON.stringify({ ttl_minutes: 15 }) })) }
		catch (err) { setError((err as Error).message) }
		finally { setBusy(false) }
	}
	const copyPairing = async () => {
		if (!pairing) return
		await navigator.clipboard.writeText(pairing.install_command); setCopied(true); window.setTimeout(() => setCopied(false), 1500)
	}
	return <div className="security-page">
		{error && <div className="alert-strip"><AlertTriangle size={18} />{error}<button onClick={() => setError('')} aria-label="关闭"><X size={16} /></button></div>}
		{message && <div className="success-strip"><Check size={18} />{message}</div>}
		<section className="detail-grid security-grid">
			<article className="panel detail-panel security-panel"><PanelHeader icon={<LockKeyhole size={21} />} title="主控信任" subtitle="Agent 固定并验证主控身份" /><dl className="detail-list"><div><dt>身份签名</dt><dd><SecurityState ok={Boolean(agent.controller_verified_at)} okText="已验证" waitingText="等待 Agent 验证" /></dd></div><div><dt>端到端通道</dt><dd><SecurityState ok={agent.secure_channel} okText="X25519 + AES-GCM" waitingText="TLS 兼容模式" /></dd></div><div><dt>主控指纹</dt><dd className="mono fingerprint">{shortFingerprint(agent.controller_key_fingerprint)}</dd></div><div><dt>验证时间</dt><dd>{formatTime(agent.controller_verified_at || '')}</dd></div></dl></article>
			<article className="panel detail-panel security-panel"><PanelHeader icon={<KeyRound size={21} />} title="Agent 凭据" subtitle="独立凭据与机器标识绑定" /><dl className="detail-list"><div><dt>凭据状态</dt><dd><CredentialState state={agent.credential_state} /></dd></div><div><dt>最近认证</dt><dd>{formatTime(agent.last_authenticated_at || '')}</dd></div><div><dt>最近轮换</dt><dd>{formatTime(agent.credential_rotated_at || '')}</dd></div><div><dt>连接来源</dt><dd className="mono">{agent.ip_address || '-'}</dd></div></dl></article>
		</section>
		<section className="settings-section security-actions"><div className="settings-heading"><div><h2>凭据操作</h2><p>轮换保留现有策略；撤销后必须重新配对</p></div></div><div className="security-action-list"><div><span><strong>轮换凭据</strong><small>在线 Agent 通过加密通道自动换钥</small></span><button className="secondary-button" disabled={busy || agent.status !== 'online' || !agent.secure_channel || agent.credential_state === 'revoked'} onClick={() => setRotateOpen(true)}><RotateCw size={17} />立即轮换</button></div><div><span><strong>重新配对</strong><small>生成绑定当前机器的一次性安装命令</small></span><button className="secondary-button" disabled={busy} onClick={() => void createPairing()}><Link2 size={17} />生成命令</button></div><div><span><strong>撤销访问</strong><small>立即断开 Agent 并拒绝旧凭据</small></span><button className="danger-button" disabled={busy || agent.credential_state === 'revoked'} onClick={() => setRevokeOpen(true)}><Link2Off size={17} />撤销凭据</button></div></div></section>
		{pairing && <section className="settings-section pairing-result"><div className="settings-heading"><div><h2>一次性重新配对命令</h2><p>{pairing.expires_in_minutes} 分钟内有效，仅接受原机器标识</p></div><button className="primary-button" onClick={() => void copyPairing()}>{copied ? <Check size={17} /> : <Copy size={17} />}{copied ? '已复制' : '复制命令'}</button></div><pre>{pairing.install_command}</pre></section>}
		{rotateOpen && <ConfirmDialog title="轮换 Agent 凭据" description="新凭据会经端到端加密通道下发，Agent 随后自动重连，现有防护规则不会中断。" confirmLabel="确认轮换" busy={busy} onClose={() => setRotateOpen(false)} onConfirm={rotate} />}
		{revokeOpen && <ConfirmDialog title="撤销 Agent 凭据" description="当前连接会立即断开。恢复连接需要在原服务器执行一次性重新配对命令。" confirmLabel="撤销凭据" busy={busy} danger onClose={() => setRevokeOpen(false)} onConfirm={revoke} />}
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

function ProtectionEditor({ agent, initialPolicy, onDirtyChange, onSaved }: { agent: Agent; initialPolicy: Policy | null; onDirtyChange: (dirty: boolean) => void; onSaved: (policy: Policy) => void }) {
  const discovered = discoveredPorts(agent)
  const startingPolicy = initialPolicy || defaultAgentPolicy(agent.name, discovered)
  const [policy, setPolicy] = useState<Policy>(() => startingPolicy)
  const [savedSnapshot, setSavedSnapshot] = useState(() => initialPolicy ? JSON.stringify(startingPolicy) : '')
  const [selectedSources, setSelectedSources] = useState<string[]>(() => discovered.filter(source => startingPolicy.ports.some(port => port.port === source.port)).map(source => source.key))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const dirty = JSON.stringify(policy) !== savedSnapshot

  useEffect(() => {
    onDirtyChange(dirty)
    return () => onDirtyChange(false)
  }, [dirty, onDirtyChange])
  useEffect(() => {
    if (!dirty) return
    const warn = (event: BeforeUnloadEvent) => event.preventDefault()
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [dirty])

  const updatePort = (index: number, field: keyof PortRule, value: number | boolean) => setPolicy(current => ({ ...current, ports: current.ports.map((port, portIndex) => portIndex === index ? { ...port, [field]: value } : port) }))
  const toggleSource = (source: DiscoveredPort, checked: boolean) => {
    setSelectedSources(current => checked ? [...new Set([...current, source.key])] : current.filter(key => key !== source.key))
    setPolicy(current => {
      if (checked) return current.ports.some(port => port.port === source.port) ? current : { ...current, ports: [...current.ports, plainPortRule(source.port)] }
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
    event.preventDefault(); setError(''); setMessage('')
    const validationError = validatePolicy(policy)
    if (validationError) { setError(validationError); return }
    setBusy(true)
    try {
      const result = await api<{ policy: Policy; message: string }>(`/api/admin/agents/${encodeURIComponent(agent.id)}/protection`, { method: 'PUT', body: JSON.stringify(policy) })
      setPolicy(result.policy); setSavedSnapshot(JSON.stringify(result.policy)); setMessage('已保存并只应用到这台服务器'); onSaved(result.policy)
    } catch (err) { setError((err as Error).message) }
    finally { setBusy(false) }
  }
  return <form className="protection-page" onSubmit={submit}>
    {!initialPolicy && <div className="info-strip"><ShieldCheck size={18} /><span><strong>推荐默认值，尚未应用</strong><small>检查端口和可信入口后，点击“保存并应用”才会在这台服务器启用。</small></span></div>}
    {error && <div className="alert-strip"><AlertTriangle size={18} />{error}</div>}
    {message && <div className="success-strip"><Check size={18} />{message}</div>}
    <section className="settings-section">
      <div className="settings-heading"><div><h2>防护范围</h2><p>从这台机器实际发现的服务端口中选择</p></div><label className="switch-field"><input type="checkbox" checked={policy.enabled} onChange={event => setPolicy(current => ({ ...current, enabled: event.target.checked }))} /><span>启用防护</span></label></div>
      <div className="discovered-list">{discovered.map(source => <label key={source.key} className={!source.tcp ? 'disabled' : ''}><input type="checkbox" disabled={!source.tcp} checked={selectedSources.includes(source.key)} onChange={event => toggleSource(source, event.target.checked)} /><span className={`service-mark ${source.kind}`}><source.icon size={18} /></span><span className="discovered-main"><strong>{source.title}</strong><small className="mono">{source.detail}</small></span><span className={`rule-state ${source.active ? 'active' : ''}`}>{source.active ? '运行中' : '已配置，未运行'}</span></label>)}{discovered.length === 0 && <Empty text="尚未发现妙妙屋节点或 ForwardX 入口，可在下方手工添加端口" />}</div>
    </section>
    <section className="settings-section">
      <div className="settings-heading"><div><h2>端口阈值</h2><p>超过弹性额度时只丢弃新的 TCP 握手</p></div></div>
      <div className="port-settings">{policy.ports.map((port, index) => <div className="port-editor" key={`${port.port}-${index}`}><div className="editor-title"><strong>TCP :{port.port}</strong><button type="button" onClick={() => removePort(index)} title="删除端口规则" aria-label={`删除端口 ${port.port} 规则`}><Trash2 size={17} /></button></div><div className="five-cols"><NumberField label="端口" value={port.port} onChange={value => updatePort(index, 'port', value)} /><NumberField label="单 IP 速率 /s" value={port.per_ip_rate} onChange={value => updatePort(index, 'per_ip_rate', value)} /><NumberField label="单 IP 突发" value={port.per_ip_burst} onChange={value => updatePort(index, 'per_ip_burst', value)} /><NumberField label="端口总速率 /s" value={port.aggregate_rate} onChange={value => updatePort(index, 'aggregate_rate', value)} /><NumberField label="端口总突发" value={port.aggregate_burst} onChange={value => updatePort(index, 'aggregate_burst', value)} /></div></div>)}
        <button type="button" className="add-rule" onClick={() => setPolicy(current => ({ ...current, ports: [...current.ports, plainPortRule(443)] }))}><Plus size={17} />增加手工端口</button>
      </div>
    </section>
    <section className="settings-section">
      <div className="settings-heading"><div><h2>整机与可信入口</h2><p>可信前置地址不受速率限制，管理端口始终排除</p></div><label className="switch-field"><input type="checkbox" checked={policy.global.enabled} onChange={event => setPolicy(current => ({ ...current, global: { ...current.global, enabled: event.target.checked } }))} /><span>整机规则</span></label></div>
      <div className="form-grid settings-fields"><label><span>策略名称</span><input value={policy.name} maxLength={80} onChange={event => setPolicy(current => ({ ...current, name: event.target.value }))} required /></label><NumberField label="整机 SYN 速率 /s" value={policy.global.rate} onChange={value => setPolicy(current => ({ ...current, global: { ...current.global, rate: value } }))} /><NumberField label="整机突发额度" value={policy.global.burst} onChange={value => setPolicy(current => ({ ...current, global: { ...current.global, burst: value } }))} /><label><span>永久排除端口</span><input value={policy.global.exempt_ports.join(',')} onChange={event => setPolicy(current => ({ ...current, global: { ...current.global, exempt_ports: event.target.value.split(',').map(Number).filter(Boolean) } }))} placeholder="22,48357" /></label><label className="full"><span>可信前置 IP / CIDR</span><textarea value={policy.trusted_cidrs.join('\n')} onChange={event => setPolicy(current => ({ ...current, trusted_cidrs: event.target.value.split(/[\s,]+/).filter(Boolean) }))} placeholder="每行一个，例如 212.17.236.133/32" /></label></div>
    </section>
    <div className="settings-actions"><span>{agent.status !== 'online' ? '服务器离线，暂时无法应用' : dirty ? '有未保存修改，保存后立即应用到当前服务器' : '当前设置已保存'}</span><button className="primary-button" disabled={busy || agent.status !== 'online' || !dirty}><Save size={18} />{busy ? '正在应用...' : '保存并应用'}</button></div>
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
  const [query, setQuery] = useState('')
  const [level, setLevel] = useState('all')
  const [agentID, setAgentID] = useState('all')
  const [kind, setKind] = useState('all')
  const kinds = useMemo(() => [...new Set(events.map(event => event.kind))].sort(), [events])
	const visibleEvents = useMemo(() => {
		const needle = query.trim().toLowerCase()
		return events.filter(event => {
			const serverName = names[event.agent_id || ''] || event.agent_id || ''
			const kindLabel = eventKindLabel(event.kind)
			return (level === 'all' || event.level === level) &&
				(agentID === 'all' || event.agent_id === agentID) &&
				(kind === 'all' || event.kind === kind) &&
				(!needle || `${event.message} ${serverName} ${event.kind} ${kindLabel}`.toLowerCase().includes(needle))
		})
  }, [agentID, events, kind, level, names, query])
  return <section className="panel management-panel"><div className="section-toolbar"><div><h2>安全事件 ({visibleEvents.length} / {events.length})</h2><p>登录、策略下发与 Agent 生命周期审计</p></div><span className="toolbar-label"><Filter size={17} />筛选事件</span></div>
    <div className="list-controls events-controls" role="search"><label className="search-field"><Search size={17} /><span className="sr-only">搜索事件</span><input value={query} onChange={event => setQuery(event.target.value)} placeholder="搜索事件、服务器或类型" /></label><label><span className="sr-only">事件级别</span><select value={level} onChange={event => setLevel(event.target.value)}><option value="all">全部级别</option><option value="info">信息</option><option value="warning">警告</option><option value="error">失败</option></select></label>{agents.length > 1 && <label><span className="sr-only">服务器</span><select value={agentID} onChange={event => setAgentID(event.target.value)}><option value="all">全部服务器</option>{agents.map(agent => <option key={agent.id} value={agent.id}>{agent.name}</option>)}</select></label>}<label><span className="sr-only">事件类型</span><select value={kind} onChange={event => setKind(event.target.value)}><option value="all">全部类型</option>{kinds.map(value => <option key={value} value={value}>{eventKindLabel(value)}</option>)}</select></label></div>
    <div className="table-wrap"><table><thead><tr><th>级别</th><th>时间</th><th>事件</th><th>服务器</th><th>类型</th></tr></thead><tbody>{visibleEvents.map(event => <tr key={event.id}><td><EventLevel level={event.level} /></td><td>{formatTime(event.created_at)}</td><td>{event.message}</td><td>{names[event.agent_id || ''] || event.agent_id || '-'}</td><td><span className="event-kind">{eventKindLabel(event.kind)}</span></td></tr>)}{visibleEvents.length === 0 && <tr><td colSpan={5}><Empty text={events.length === 0 ? '暂无事件' : '没有符合筛选条件的事件'} /></td></tr>}</tbody></table></div>
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

function PasswordDialog({ onClose }: { onClose: () => void }) {
	const [currentPassword, setCurrentPassword] = useState('')
	const [newPassword, setNewPassword] = useState('')
	const [confirmPassword, setConfirmPassword] = useState('')
	const [busy, setBusy] = useState(false)
	const [error, setError] = useState('')
	const submit = async (event: FormEvent) => {
		event.preventDefault(); setError('')
		if (newPassword !== confirmPassword) { setError('两次输入的新密码不一致'); return }
		setBusy(true)
		try {
			await api('/api/admin/account/password', { method: 'POST', body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }) })
			onClose()
		} catch (err) { setError((err as Error).message) }
		finally { setBusy(false) }
	}
	return <Modal title="修改管理员密码" subtitle="保存后其他登录会话立即失效" returnFocus=".admin-menu" onClose={busy ? () => undefined : onClose}>
		<form className="form-grid" onSubmit={submit}>{error && <div className="form-error full" role="alert">{error}</div>}<label className="full"><span>当前密码</span><input autoFocus type="password" autoComplete="current-password" value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} required /></label><label className="full"><span>新密码</span><input type="password" autoComplete="new-password" minLength={10} maxLength={72} value={newPassword} onChange={event => setNewPassword(event.target.value)} required /></label><label className="full"><span>确认新密码</span><input type="password" autoComplete="new-password" minLength={10} maxLength={72} value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} required /></label><div className="dialog-actions"><button type="button" className="secondary-button" disabled={busy} onClick={onClose}>取消</button><button className="primary-button" disabled={busy || newPassword.length < 10}>{busy ? '正在保存...' : '修改密码'}</button></div></form>
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

function AuthScreen({ setup, turnstileSiteKey, onAuthenticated }: { setup: boolean; turnstileSiteKey: string; onAuthenticated: () => Promise<void> }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [turnstileToken, setTurnstileToken] = useState('')
  const [challengeKey, setChallengeKey] = useState(0)
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setError('')
    if (turnstileSiteKey && !turnstileToken) { setError('请先完成人机验证'); return }
    setBusy(true)
    try { await api(setup ? '/api/setup' : '/api/login', { method: 'POST', body: JSON.stringify({ username, password, turnstile_token: turnstileToken }) }); await onAuthenticated() }
    catch (err) { setError((err as Error).message); setTurnstileToken(''); setChallengeKey(key => key + 1) }
    finally { setBusy(false) }
  }
  return <div className="auth-screen login-pixel-bg"><section className="auth-window"><header className="auth-card-header"><img src="/images/logo.webp" alt="妙妙屋 Logo" /><h1>{setup ? '欢迎使用妙妙屋X安全防护' : '登录妙妙屋X安全防护'}</h1><p>{setup ? '这是首次启动，请创建管理员账号' : '请输入管理员账号以访问安全防护后台'}</p></header><form onSubmit={submit}>{error && <div className="form-error" role="alert">{error}</div>}<label><span>用户名</span><input autoFocus autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} placeholder="请输入用户名" required /></label><label><span>密码</span><input type="password" autoComplete={setup ? 'new-password' : 'current-password'} value={password} onChange={e => setPassword(e.target.value)} placeholder={setup ? '至少 10 位' : '请输入密码'} required /></label>{turnstileSiteKey && <TurnstileWidget key={challengeKey} siteKey={turnstileSiteKey} onToken={setTurnstileToken} />}<button className="primary-button auth-submit" disabled={busy || Boolean(turnstileSiteKey && !turnstileToken)}>{busy ? (setup ? '创建中...' : '登录中...') : setup ? '创建管理员账号' : '登录'}</button></form></section></div>
}

type TurnstileAPI = {
  render: (container: HTMLElement, options: Record<string, unknown>) => string
  remove: (widgetID: string) => void
}

function TurnstileWidget({ siteKey, onToken }: { siteKey: string; onToken: (token: string) => void }) {
  const [container, setContainer] = useState<HTMLDivElement | null>(null)
  useEffect(() => {
    if (!container) return
    let active = true
    let widgetID = ''
    const render = () => {
      const turnstile = (window as typeof window & { turnstile?: TurnstileAPI }).turnstile
      if (!active || !turnstile) return
      container.replaceChildren()
      widgetID = turnstile.render(container, {
        sitekey: siteKey, action: 'login', theme: 'auto', size: 'flexible',
        callback: (token: string) => onToken(token),
        'expired-callback': () => onToken(''),
        'error-callback': () => onToken(''),
      })
    }
    const existing = document.querySelector<HTMLScriptElement>('script[data-mmwx-turnstile]')
    if (existing) {
      if ((window as typeof window & { turnstile?: TurnstileAPI }).turnstile) render()
      else existing.addEventListener('load', render, { once: true })
    } else {
      const script = document.createElement('script')
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
      script.async = true
      script.defer = true
      script.dataset.mmwxTurnstile = 'true'
      script.addEventListener('load', render, { once: true })
      document.head.appendChild(script)
    }
    return () => {
      active = false
      onToken('')
      const turnstile = (window as typeof window & { turnstile?: TurnstileAPI }).turnstile
      if (widgetID && turnstile) turnstile.remove(widgetID)
    }
  }, [container, onToken, siteKey])
  return <div className="turnstile-slot" ref={setContainer} aria-label="Cloudflare 人机验证" />
}

function Modal({ title, subtitle, onClose, children, wide = false, returnFocus }: { title: string; subtitle: string; onClose: () => void; children: ReactNode; wide?: boolean; returnFocus?: string }) {
	const dialogRef = useRef<HTMLElement>(null)
	const onCloseRef = useRef(onClose)
	onCloseRef.current = onClose
	useEffect(() => {
		const previous = document.activeElement as HTMLElement | null
		const dialog = dialogRef.current
		const focusable = () => [...(dialog?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href]') || [])]
		const initial = dialog?.querySelector<HTMLElement>('[data-initial-focus]') || dialog?.querySelector<HTMLElement>('.modal-body input:not(:disabled), .modal-body select:not(:disabled), .modal-body textarea:not(:disabled)')
		const focusTimer = window.setTimeout(() => (initial || focusable()[0] || dialog)?.focus(), 0)
		const handleKey = (event: KeyboardEvent) => {
			if (event.key === 'Escape') { onCloseRef.current(); return }
			if (event.key !== 'Tab') return
			const items = focusable()
			if (items.length === 0) { event.preventDefault(); return }
			const first = items[0]
			const last = items[items.length - 1]
			if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
			else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
		}
		window.addEventListener('keydown', handleKey)
		return () => { window.clearTimeout(focusTimer); window.removeEventListener('keydown', handleKey); (returnFocus ? document.querySelector<HTMLElement>(returnFocus) : previous)?.focus() }
	}, [])
	return <div className="modal-backdrop" role="presentation" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}><section ref={dialogRef} tabIndex={-1} className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={title}><header><div><h2>{title}</h2><p>{subtitle}</p></div><button className="icon-button" onClick={onClose} title="关闭" aria-label="关闭"><X size={20} /></button></header><div className="modal-body">{children}</div></section></div>
}

function ConfirmDialog({ title, description, confirmLabel, busy = false, danger = false, returnFocus, onClose, onConfirm }: { title: string; description: string; confirmLabel: string; busy?: boolean; danger?: boolean; returnFocus?: string; onClose: () => void; onConfirm: () => void | Promise<void> }) {
		  return <Modal title={title} subtitle="请确认本次操作" returnFocus={returnFocus} onClose={busy ? () => undefined : onClose}><div className="confirm-dialog"><AlertTriangle size={24} /><p>{description}</p><div className="dialog-actions"><button data-initial-focus className="secondary-button" disabled={busy} onClick={onClose}>取消</button><button className={danger ? 'danger-button' : 'primary-button'} disabled={busy} onClick={() => void onConfirm()}>{busy ? '正在处理...' : confirmLabel}</button></div></div></Modal>
}

function Metric({ icon, title, value, detail, tone }: { icon: ReactNode; title: string; value: string; detail: string; tone: string }) { return <article className={`metric ${tone}`}><div className="metric-head"><h2>{title}</h2><span>{icon}</span></div><p>{detail}</p><strong>{value}</strong></article> }
function PanelHeader({ icon, title, subtitle }: { icon: ReactNode; title: string; subtitle: string }) { return <div className="panel-header"><span>{icon}</span><div><h2>{title}</h2><p>{subtitle}</p></div></div> }
function Empty({ text }: { text: string }) { return <div className="empty"><Clipboard size={26} /><span>{text}</span></div> }
function NumberField({ label, value, onChange, disabled = false }: { label: string; value: number; onChange: (v: number) => void; disabled?: boolean }) { return <label><span>{label}</span><input type="number" min="1" value={value} onChange={e => onChange(Number(e.target.value))} disabled={disabled} required /></label> }
function Status({ status, protected: active }: { status: string; protected?: boolean }) { return <span className={`status ${status}`}><i />{status === 'online' ? (active ? '防护中' : '在线') : '离线'}</span> }
function AgentStatus({ agent }: { agent: Agent }) {
	if (agent.credential_state === 'revoked') return <span className="status revoked"><i />已撤销</span>
	if (agent.credential_state === 'rotation_pending') return <span className="status pending"><i />换钥中</span>
	return <Status status={agent.status} protected={agent.telemetry?.protected} />
}
function SecurityState({ ok, okText, waitingText }: { ok: boolean; okText: string; waitingText: string }) { return <span className={`security-state ${ok ? 'ok' : 'waiting'}`}>{ok ? <ShieldCheck size={15} /> : <AlertTriangle size={15} />}{ok ? okText : waitingText}</span> }
function CredentialState({ state }: { state: Agent['credential_state'] }) { const values = { active: ['active', '有效'], rotation_pending: ['pending', '等待新凭据上线'], revoked: ['revoked', '已撤销'] } as const; const value = values[state] || values.active; return <span className={`credential-state ${value[0]}`}>{value[1]}</span> }
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
function plainPortRule(port: number): PortRule { return { port, per_ip_rate: 100, per_ip_burst: 500, aggregate_rate: 300, aggregate_burst: 1500, enabled: true } }
function newPortRule(port: number, manual: boolean): EditablePortRule { return { ...plainPortRule(port), manual, source_rules: [] } }

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
  const ports = [...new Set(sources.filter(source => source.tcp).map(source => source.port))].map(plainPortRule)
  return { id: 0, revision: 1, name: `${name} 防护`, enabled: true, ports, global: { rate: 800, burst: 4000, exempt_ports: [22, 48357], enabled: true }, trusted_cidrs: [], syn_sent_timeout: 15, syn_recv_timeout: 30 }
}
function formatListen(listen: string | undefined, port: number) { return `${listen || '0.0.0.0'}:${port}` }

function shortFingerprint(value?: string) { return value ? `${value.slice(0, 12)}...${value.slice(-12)}` : '-' }
function agentNeedsAttention(agent: Agent) {
	const telemetry = agent.telemetry
	if (agent.status !== 'online' || agent.credential_state !== 'active' || !agent.secure_channel || !agent.controller_verified_at) return true
	if (!telemetry) return true
	return (telemetry.cpu_usage || 0) >= 90 || (telemetry.memory_total > 0 && telemetry.memory_used / telemetry.memory_total >= .9) || (telemetry.conntrack_max > 0 && telemetry.conntrack / telemetry.conntrack_max >= .8) || telemetry.sockets.syn_recv >= 1000
}

function validatePolicy(policy: Policy) {
  if (!policy.name.trim()) return '请输入策略名称'
  const ports = new Set<number>()
  for (const rule of policy.ports) {
    if (!Number.isInteger(rule.port) || rule.port < 1 || rule.port > 65535) return '端口必须是 1 到 65535 的整数'
    if (ports.has(rule.port)) return `端口 ${rule.port} 重复，请合并为一条规则`
    ports.add(rule.port)
    if (!rule.enabled) continue
    if (rule.per_ip_rate < 1 || rule.per_ip_burst < rule.per_ip_rate) return `端口 ${rule.port} 的单 IP 突发额度不能低于速率`
    if (rule.aggregate_rate < rule.per_ip_rate) return `端口 ${rule.port} 的总速率不能低于单 IP 速率`
    if (rule.aggregate_burst < rule.aggregate_rate) return `端口 ${rule.port} 的总突发额度不能低于总速率`
  }
  if (policy.global.enabled && (policy.global.rate < 1 || policy.global.burst < policy.global.rate)) return '整机突发额度不能低于整机 SYN 速率'
  if (policy.global.exempt_ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) return '永久排除端口必须是 1 到 65535 的整数'
  return ''
}

function eventKindLabel(kind: string) {
	  const labels: Record<string, string> = {
	    system_setup: '系统初始化', login_succeeded: '登录成功', login_failed: '登录失败', login_limited: '登录限速',
	    enrollment_created: '注册令牌', agent_enrolled: 'Agent 注册', agent_online: 'Agent 上线', agent_deleted: 'Agent 删除', agent_renamed: '名称修改',
	    agent_identity_mismatch: 'Agent 身份异常', controller_identity_mismatch: '主控身份异常', agent_credential_rotation_pending: '轮换待确认', agent_credential_rotation_failed: '轮换失败',
	    agent_credential_rotation_started: '轮换已下发', agent_credential_rotated: '凭据已轮换', agent_credential_revoked: '凭据已撤销',
	    agent_pairing_created: '重新配对令牌', agent_repaired: '重新配对完成', password_change_failed: '改密失败', password_changed: '密码已修改',
	    policy_saved: '策略保存', policy_deploy: '策略下发', agent_update: 'Agent 更新', controller_update_queued: '主控更新',
	  }
  return labels[kind] || kind
}

function readRoute(): RouteState {
  const params = new URLSearchParams(window.location.search)
  const rawTab = params.get('view')
  const rawDetail = params.get('section')
  const tabs: Tab[] = ['overview', 'agents', 'events', 'updates']
	const detailTabs: DetailTab[] = ['overview', 'protection', 'services', 'security', 'events']
  const agentID = params.get('server') || ''
  return {
    tab: tabs.includes(rawTab as Tab) ? rawTab as Tab : agentID ? 'agents' : 'overview',
    agentID,
    detailTab: detailTabs.includes(rawDetail as DetailTab) ? rawDetail as DetailTab : 'overview',
  }
}

function writeRoute(route: RouteState) {
  const params = new URLSearchParams()
  if (route.tab !== 'overview') params.set('view', route.tab)
  if (route.agentID) {
    params.set('server', route.agentID)
    if (route.detailTab !== 'overview') params.set('section', route.detailTab)
  }
  const query = params.toString()
  window.history.pushState(null, '', query ? `${window.location.pathname}?${query}` : window.location.pathname)
}

export default App
