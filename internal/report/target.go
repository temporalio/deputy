package report

// Target identifies the repository and reference for a report.
type Target struct {
	Repo   string `json:"repo"`
	Ref    string `json:"ref,omitempty"`
	Commit string `json:"commit,omitempty"`
}
