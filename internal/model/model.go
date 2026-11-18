package model

import "encoding/json"

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
	PID                  int           `json:"pid"`
	Executable           string        `json:"executable"`
	Libraries            []string      `json:"libraries,omitempty"`
	InstallHints         []string      `json:"installHints,omitempty"`
	ExecutableDeleted    bool          `json:"executableDeleted,omitempty"`
	FilesystemComparable bool          `json:"filesystemComparable,omitempty"`
	RuntimeFiles         []RuntimeFile `json:"runtimeFiles,omitempty"`
	ListeningSockets     []Socket      `json:"listeningSockets,omitempty"`
}

// Socket is a listening TCP or unconnected bound UDP socket in the collector's
// network namespace. BindScope describes the local address only; firewall and
// routing reachability are not observed.
type Socket struct {
	Protocol  string `json:"protocol"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	BindScope string `json:"bindScope"`
}

type KernelModule struct {
	Name       string `json:"name"`
	Taint      string `json:"taint"`
	Version    string `json:"version,omitempty"`
	SrcVersion string `json:"srcVersion,omitempty"`
}

type UnidentifiedExecutable struct {
	Path string `json:"path"`
	PIDs []int  `json:"pids"`
}

// HostIdentity correlates repeated collections of one machine. Identifiers are
// SHA-256 digests of the normalized local value; low-entropy serials remain
// guessable from their digest, so this is pseudonymization, not anonymization.
type HostIdentity struct {
	AssetTag            string `json:"assetTag,omitempty"`
	MachineIDSHA256     string `json:"machineIdSha256,omitempty"`
	ProductUUIDSHA256   string `json:"productUuidSha256,omitempty"`
	ProductSerialSHA256 string `json:"productSerialSha256,omitempty"`
	BoardSerialSHA256   string `json:"boardSerialSha256,omitempty"`
	ObservationScope    string `json:"observationScope,omitempty"`
}

type RuntimeFile struct {
	Path             string `json:"path"`
	Deleted          bool   `json:"deleted,omitempty"`
	Device           string `json:"device,omitempty"`
	Inode            uint64 `json:"inode,omitempty"`
	DiskInode        uint64 `json:"diskInode,omitempty"`
	State            string `json:"state"`
	Package          string `json:"package,omitempty"`
	PURL             string `json:"purl,omitempty"`
	InstalledVersion string `json:"installedVersion,omitempty"`
}

// Asset is a bounded observation of a device, firmware image or device driver.
// ParentID points to the device that contains or uses the component.
type Asset struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Name       string            `json:"name"`
	Vendor     string            `json:"vendor,omitempty"`
	Version    string            `json:"version,omitempty"`
	Model      string            `json:"model,omitempty"`
	Revision   string            `json:"revision,omitempty"`
	ParentID   string            `json:"parentId,omitempty"`
	CPE        string            `json:"cpe,omitempty"`
	PURL       string            `json:"purl,omitempty"`
	SHA256     string            `json:"sha256,omitempty"`
	Source     string            `json:"source"`
	ObservedAt string            `json:"observedAt,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
	// Crypto holds CycloneDX cryptoProperties for kind "cryptographic-asset".
	Crypto json.RawMessage `json:"cryptoProperties,omitempty"`
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
	// Loaded modules that taint the kernel: out-of-tree (O), unsigned (E) or
	// proprietary (P). Distribution kernel advisories do not cover them.
	TaintedModules []KernelModule `json:"taintedModules,omitempty"`
	// Running executables that no installed package or collector accounts for.
	UnidentifiedExecutables []UnidentifiedExecutable `json:"unidentifiedExecutables,omitempty"`
	// Sockets whose owning process could not be read or was excluded.
	UnattributedSockets []Socket  `json:"unattributedSockets,omitempty"`
	Settings            []Setting `json:"settings"`
	Issues              []Issue   `json:"issues"`
}
