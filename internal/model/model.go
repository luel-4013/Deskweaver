// Package model contains the shared data types for Deskweaver.
//
// The types in this package are serialized to plan.json and are therefore
// part of the public output contract. Keep field names and meanings stable.
package model

// Tier describes how deeply Deskweaver understands a framework.
type Tier string

const (
	TierA Tier = "A" // deep profile, safe to recommend
	TierB Tier = "B" // standard detection, recommend with a verify note
	TierC Tier = "C" // heuristic only, manual review required
)

// Confidence is a coarse, user-facing confidence band.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Evidence is one reason a detection fired.
type Evidence struct {
	Kind   string `json:"kind" yaml:"kind"`
	Path   string `json:"path,omitempty" yaml:"path,omitempty"`
	Detail string `json:"detail,omitempty" yaml:"detail,omitempty"`
	Weight int    `json:"weight,omitempty" yaml:"weight,omitempty"`
}

// Detection is a framework or stack hypothesis.
type Detection struct {
	RuleID        string     `json:"rule_id" yaml:"rule_id"`
	Name          string     `json:"name" yaml:"name"`
	Variant       string     `json:"variant,omitempty" yaml:"variant,omitempty"`
	Version       string     `json:"version,omitempty" yaml:"version,omitempty"`
	Tier          Tier       `json:"tier" yaml:"tier"`
	Language      string     `json:"language" yaml:"language"`
	Confidence    Confidence `json:"confidence" yaml:"confidence"`
	Score         int        `json:"score" yaml:"score"`
	Evidence      []Evidence `json:"evidence" yaml:"evidence"`
	Capabilities  []string   `json:"capabilities" yaml:"capabilities"`
	DefaultTarget string     `json:"default_target" yaml:"default_target"`
	Notes         string     `json:"notes,omitempty" yaml:"notes,omitempty"`
	ManualReview  bool       `json:"manual_review" yaml:"manual_review"`
}

// Project is the read-only profile produced by the scanner.
type Project struct {
	Schema       string      `json:"schema" yaml:"schema"`
	Name         string      `json:"name" yaml:"name"`
	Root         string      `json:"root" yaml:"root"`
	ScannedFiles int         `json:"scanned_files" yaml:"scanned_files"`
	SkippedFiles int         `json:"skipped_files" yaml:"skipped_files"`
	Truncated    bool        `json:"truncated" yaml:"truncated"`
	Monorepo     bool        `json:"monorepo" yaml:"monorepo"`
	Workspaces   []string    `json:"workspaces,omitempty" yaml:"workspaces,omitempty"`
	Detections   []Detection `json:"detections" yaml:"detections"`
	Primary      *Detection  `json:"primary,omitempty" yaml:"primary,omitempty"`
	Capabilities []string    `json:"capabilities" yaml:"capabilities"`
	Unknowns     []string    `json:"unknowns,omitempty" yaml:"unknowns,omitempty"`
	Warnings     []string    `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

// OSSupport describes how well a technology works on one operating system.
// Level is S0-S4: 0 unsupported, 1 experimental, 2 works with caveats,
// 3 supported/tested, 4 hardened and distribution-ready.
type OSSupport struct {
	OS      string   `json:"os" yaml:"os"`
	Level   int      `json:"level" yaml:"level"`
	Label   string   `json:"label" yaml:"label"`
	Formats []string `json:"formats,omitempty" yaml:"formats,omitempty"`
	Notes   string   `json:"notes,omitempty" yaml:"notes,omitempty"`
}

// RankedCandidate is a recommendation result.
type RankedCandidate struct {
	ID     string `json:"id" yaml:"id"`
	Name   string `json:"name" yaml:"name"`
	Score  int    `json:"score" yaml:"score"`
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// Recommendation is the explainable output of the recommendation engine.
type Recommendation struct {
	Primary          *RankedCandidate  `json:"primary,omitempty" yaml:"primary,omitempty"`
	Fallback         *RankedCandidate  `json:"fallback,omitempty" yaml:"fallback,omitempty"`
	Rejected         []RankedCandidate `json:"rejected,omitempty" yaml:"rejected,omitempty"`
	Reasons          []string          `json:"reasons" yaml:"reasons"`
	Tradeoffs        []string          `json:"tradeoffs,omitempty" yaml:"tradeoffs,omitempty"`
	Sensitivity      string            `json:"sensitivity,omitempty" yaml:"sensitivity,omitempty"`
	OSMatrix         []OSSupport       `json:"os_matrix,omitempty" yaml:"os_matrix,omitempty"`
	RequestedTargets []string          `json:"requested_targets" yaml:"requested_targets"`
	Architecture     string            `json:"architecture,omitempty" yaml:"architecture,omitempty"`
	Blockers         []string          `json:"blockers,omitempty" yaml:"blockers,omitempty"`
	Unknowns         []string          `json:"unknowns,omitempty" yaml:"unknowns,omitempty"`
	ManualReview     bool              `json:"manual_review" yaml:"manual_review"`
}

// HostTool is one toolchain or library found on the build host.
type HostTool struct {
	Name     string `json:"name" yaml:"name"`
	Found    bool   `json:"found" yaml:"found"`
	Path     string `json:"path,omitempty" yaml:"path,omitempty"`
	Version  string `json:"version,omitempty" yaml:"version,omitempty"`
	Required bool   `json:"required" yaml:"required"`
	Detail   string `json:"detail,omitempty" yaml:"detail,omitempty"`
}

// HostCheck is a doctor result with copy-pasteable remediation.
type HostCheck struct {
	Name    string `json:"name" yaml:"name"`
	Status  string `json:"status" yaml:"status"` // ok, missing, warn, info
	Detail  string `json:"detail,omitempty" yaml:"detail,omitempty"`
	Install string `json:"install,omitempty" yaml:"install,omitempty"`
	Verify  string `json:"verify,omitempty" yaml:"verify,omitempty"`
}

// Host is the read-only build-host profile.
type Host struct {
	OS             string      `json:"os" yaml:"os"`
	Distro         string      `json:"distro,omitempty" yaml:"distro,omitempty"`
	Version        string      `json:"version,omitempty" yaml:"version,omitempty"`
	Family         string      `json:"family,omitempty" yaml:"family,omitempty"`
	Arch           string      `json:"arch" yaml:"arch"`
	Kernel         string      `json:"kernel,omitempty" yaml:"kernel,omitempty"`
	Session        string      `json:"session,omitempty" yaml:"session,omitempty"`
	PackageManager string      `json:"package_manager,omitempty" yaml:"package_manager,omitempty"`
	Tools          []HostTool  `json:"tools,omitempty" yaml:"tools,omitempty"`
	Webviews       []HostTool  `json:"webviews,omitempty" yaml:"webviews,omitempty"`
	Checks         []HostCheck `json:"checks,omitempty" yaml:"checks,omitempty"`
	Warnings       []string    `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

// ThreatModel is the user's security-relevant context.
type ThreatModel struct {
	Sensitivity    string `json:"sensitivity" yaml:"sensitivity"`
	UntrustedInput bool   `json:"untrusted_input" yaml:"untrusted_input"`
	Network        string `json:"network" yaml:"network"`
	Privilege      string `json:"privilege" yaml:"privilege"`
}

// Control is one security control in the generated plan.
type Control struct {
	ID     string `json:"id" yaml:"id"`
	Name   string `json:"name" yaml:"name"`
	Status string `json:"status" yaml:"status"` // required, recommended, optional
	Detail string `json:"detail" yaml:"detail"`
}

// SecurityPlan is the threat-model-driven hardening output.
type SecurityPlan struct {
	Profile       string      `json:"profile" yaml:"profile"`
	ThreatModel   ThreatModel `json:"threat_model" yaml:"threat_model"`
	Controls      []Control   `json:"controls" yaml:"controls"`
	ResidualRisks []string    `json:"residual_risks,omitempty" yaml:"residual_risks,omitempty"`
	Checklist     []string    `json:"checklist,omitempty" yaml:"checklist,omitempty"`
}

// Answers is the reviewed decision set. It is written to answers.yaml and can
// be replayed with --answers for a deterministic, non-interactive run.
type Answers struct {
	ProjectPath    string   `json:"project_path" yaml:"project_path"`
	Workspace      string   `json:"workspace,omitempty" yaml:"workspace,omitempty"`
	Targets        []string `json:"targets" yaml:"targets"`
	Formats        []string `json:"formats,omitempty" yaml:"formats,omitempty"`
	Profile        string   `json:"profile" yaml:"profile"`
	Sensitivity    string   `json:"sensitivity" yaml:"sensitivity"`
	UntrustedInput bool     `json:"untrusted_input" yaml:"untrusted_input"`
	Network        string   `json:"network" yaml:"network"`
	Privilege      string   `json:"privilege" yaml:"privilege"`
	OutputDir      string   `json:"output_dir" yaml:"output_dir"`
	GenerateKit    bool     `json:"generate_kit" yaml:"generate_kit"`
	Framework      string   `json:"framework,omitempty" yaml:"framework,omitempty"`
	Candidate      string   `json:"candidate,omitempty" yaml:"candidate,omitempty"`
	Force          bool     `json:"-" yaml:"-"`
	NoInput        bool     `json:"-" yaml:"-"`
	JSON           bool     `json:"-" yaml:"-"`
	Redact         bool     `json:"-" yaml:"-"`
	Offline        bool     `json:"-" yaml:"-"`
}

// Plan is the complete, reviewable output.
type Plan struct {
	Schema           string         `json:"schema" yaml:"schema"`
	ToolVersion      string         `json:"tool_version" yaml:"tool_version"`
	RulesVersion     string         `json:"rules_version" yaml:"rules_version"`
	RulesHash        string         `json:"rules_hash" yaml:"rules_hash"`
	GeneratedAt      string         `json:"generated_at" yaml:"generated_at"`
	PlanHash         string         `json:"plan_hash" yaml:"plan_hash"`
	Project          Project        `json:"project" yaml:"project"`
	Answers          Answers        `json:"answers" yaml:"answers"`
	Host             Host           `json:"host" yaml:"host"`
	Recommendation   Recommendation `json:"recommendation" yaml:"recommendation"`
	Security         SecurityPlan   `json:"security" yaml:"security"`
	Artifacts        []string       `json:"artifacts,omitempty" yaml:"artifacts,omitempty"`
	ArtifactManifest string         `json:"artifact_manifest,omitempty" yaml:"artifact_manifest,omitempty"`
}

// OSLabel returns the canonical S-level label.
func OSLabel(level int) string {
	switch level {
	case 0:
		return "S0 — unsupported"
	case 1:
		return "S1 — experimental"
	case 2:
		return "S2 — works with caveats"
	case 3:
		return "S3 — supported and tested"
	case 4:
		return "S4 — hardened / distribution-ready"
	default:
		return "S? — unknown"
	}
}
