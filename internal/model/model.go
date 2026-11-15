package model

type Issue struct {
	Target    string `json:"target,omitempty"`
	Collector string `json:"collector"`
	Status    string `json:"status"`
	Path      string `json:"path,omitempty"`
	Message   string `json:"message"`
	Code      string `json:"code,omitempty"`
	Limit     int64  `json:"limit,omitempty"`
	Observed  int64  `json:"observed,omitempty"`
}
type Evidence struct {
	Path  string `json:"path"`
	Field string `json:"field"`
	Value string `json:"value"`
}
type Product struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Version     string     `json:"version,omitempty"`
	Vendor      string     `json:"vendor,omitempty"`
	Kind        string     `json:"kind"`
	InstallPath string     `json:"installPath"`
	Evidence    []Evidence `json:"evidence"`
	PatchIDs    []string   `json:"patchIds,omitempty"`
	PatchState  string     `json:"patchState"`
	Confidence  string     `json:"confidence"`
}
type Setting struct {
	Product string `json:"product"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Path    string `json:"path"`
	State   string `json:"state"`
}
type ProcessLink struct {
	PID          int      `json:"pid"`
	Executable   string   `json:"executable"`
	Libraries    []string `json:"libraries,omitempty"`
	InstallHints []string `json:"installHints,omitempty"`
}

// LivepatchStatus describes evidence from one local kernel or client source.
// Status is the observation result; each patch carries its own application state.
type LivepatchStatus struct {
	Provider         string           `json:"provider"`
	EvidenceKind     string           `json:"evidenceKind"`
	Source           string           `json:"source"`
	Status           string           `json:"status"`
	ObservedAt       string           `json:"observedAt,omitempty"`
	CapturedAt       string           `json:"capturedAt,omitempty"`
	ClientReportedAt string           `json:"clientReportedAt,omitempty"`
	ClientCheckState string           `json:"clientCheckState,omitempty"`
	ReportedKernel   string           `json:"reportedKernel,omitempty"`
	EffectiveKernel  string           `json:"effectiveKernel,omitempty"`
	EvidenceSHA256   string           `json:"evidenceSHA256,omitempty"`
	Patches          []LivepatchPatch `json:"patches"`
	Limitations      []string         `json:"limitations"`
}
type LivepatchPatch struct {
	ID            string   `json:"id"`
	State         string   `json:"state"`
	ReportedState string   `json:"reportedState,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty"`
	Transition    *bool    `json:"transition,omitempty"`
	CVEs          []string `json:"cves,omitempty"`
}
type Context struct {
	Mode          string            `json:"mode"`
	Status        string            `json:"status"`
	RunningKernel string            `json:"runningKernel,omitempty"`
	KernelFlavor  string            `json:"kernelFlavor,omitempty"`
	LoadedModules []string          `json:"loadedModules,omitempty"`
	ProcessLinks  []ProcessLink     `json:"processLinks,omitempty"`
	Livepatch     []LivepatchStatus `json:"livepatch,omitempty"`
	Settings      []Setting         `json:"settings"`
	Issues        []Issue           `json:"issues"`
}
