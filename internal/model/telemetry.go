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
