package model

const AgentTaskMaxAttempts = 10

type AgentTask struct {
	ID         int64  `json:"id"`
	AgentID    string `json:"agent_id"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
	Message    string `json:"message,omitempty"`
	Attempts   int    `json:"attempts"`
	CreatedAt  string `json:"created_at"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	UpdatedAt  string `json:"updated_at"`
}

type PolicyDeployTask struct {
	PolicyID         int64  `json:"policy_id"`
	PreviousPolicyID int64  `json:"previous_policy_id,omitempty"`
	Author           string `json:"author"`
	Source           string `json:"source"`
}
