package model

type SourceCount struct {
	IP          string `json:"ip"`
	Connections int    `json:"connections"`
	Dropped     uint64 `json:"dropped,omitempty"`
}

type SocketStats struct {
	Total       int `json:"total"`
	Established int `json:"established"`
	SynRecv     int `json:"syn_recv"`
	SynSent     int `json:"syn_sent"`
	TimeWait    int `json:"time_wait"`
}

type MMWIntegration struct {
	Active         bool              `json:"active"`
	MasterURL      string            `json:"master_url,omitempty"`
	ConnectionMode string            `json:"connection_mode,omitempty"`
	XrayMode       string            `json:"xray_mode,omitempty"`
	Nodes          []MMWNodeListener `json:"nodes"`
}

type MMWNodeListener struct {
	Tag      string `json:"tag,omitempty"`
	Listen   string `json:"listen,omitempty"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Network  string `json:"network,omitempty"`
	Security string `json:"security,omitempty"`
	Active   bool   `json:"active"`
}

type ForwardRule struct {
	ID         string `json:"id"`
	Protocol   string `json:"protocol"`
	Listen     string `json:"listen"`
	ListenPort uint16 `json:"listen_port"`
	Remote     string `json:"remote"`
	Active     bool   `json:"active"`
}

type ForwardXIntegration struct {
	Active   bool          `json:"active"`
	PanelURL string        `json:"panel_url,omitempty"`
	Rules    []ForwardRule `json:"rules"`
}

type Integrations struct {
	MMW      *MMWIntegration      `json:"mmw,omitempty"`
	ForwardX *ForwardXIntegration `json:"forwardx,omitempty"`
}

type Telemetry struct {
	CollectedAt    string        `json:"collected_at"`
	CPUUsage       float64       `json:"cpu_usage"`
	Load1          float64       `json:"load_1"`
	Load5          float64       `json:"load_5"`
	MemoryUsed     uint64        `json:"memory_used"`
	MemoryTotal    uint64        `json:"memory_total"`
	Sockets        SocketStats   `json:"sockets"`
	Conntrack      uint64        `json:"conntrack"`
	ConntrackMax   uint64        `json:"conntrack_max"`
	DroppedTotal   uint64        `json:"dropped_total"`
	Protected      bool          `json:"protected"`
	PolicyRevision int64         `json:"policy_revision"`
	TopSources     []SourceCount `json:"top_sources"`
	Integrations   Integrations  `json:"integrations"`
}

type AgentSummary struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Status         string     `json:"status"`
	IPAddress      string     `json:"ip_address"`
	OS             string     `json:"os"`
	Arch           string     `json:"arch"`
	Version        string     `json:"version"`
	LastSeen       string     `json:"last_seen"`
	PolicyID       int64      `json:"policy_id,omitempty"`
	PolicyName     string     `json:"policy_name,omitempty"`
	PolicyRevision int64      `json:"policy_revision,omitempty"`
	Telemetry      *Telemetry `json:"telemetry,omitempty"`
}
