package model

type PolicyHistory struct {
	ID        int64  `json:"id"`
	AgentID   string `json:"agent_id"`
	Revision  int64  `json:"revision"`
	Source    string `json:"source"`
	Author    string `json:"author"`
	Message   string `json:"message,omitempty"`
	Policy    Policy `json:"policy"`
	CreatedAt string `json:"created_at"`
}
