package model

type IPBan struct {
	ID        int64  `json:"id"`
	AgentID   string `json:"agent_id"`
	Address   string `json:"address"`
	Reason    string `json:"reason,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	CreatedAt string `json:"created_at"`
	Applied   bool   `json:"applied"`
	LastError string `json:"last_error,omitempty"`
}

type BanTarget struct {
	Address   string `json:"address"`
	ExpiresAt string `json:"expires_at,omitempty"`
}
