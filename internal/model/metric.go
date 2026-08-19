package model

type MetricPoint struct {
	Timestamp        string  `json:"timestamp"`
	CPUUsage         float64 `json:"cpu_usage"`
	MemoryPercent    float64 `json:"memory_percent"`
	ReceiveRate      uint64  `json:"receive_rate"`
	TransmitRate     uint64  `json:"transmit_rate"`
	Established      int     `json:"established"`
	TimeWait         int     `json:"time_wait"`
	SynRecv          int     `json:"syn_recv"`
	Conntrack        uint64  `json:"conntrack"`
	ConntrackPercent float64 `json:"conntrack_percent"`
	DroppedTotal     uint64  `json:"dropped_total"`
	DroppedDelta     uint64  `json:"dropped_delta"`
	Emergency        bool    `json:"emergency"`
}
