// Package app orchestrates scanning, recommendation, host checks, security
// planning, and review-kit generation.
//
// The package performs no project writes and executes no project code. Its
// only write is the generated review directory, produced atomically by the kit
// package after the plan has been fully assembled in memory.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/luel-4013/deskweaver/internal/doctor"
	"github.com/luel-4013/deskweaver/internal/kit"
	"github.com/luel-4013/deskweaver/internal/model"
	"github.com/luel-4013/deskweaver/internal/recommend"
	"github.com/luel-4013/deskweaver/internal/rules"
	"github.com/luel-4013/deskweaver/internal/scan"
	"github.com/luel-4013/deskweaver/internal/security"
	"github.com/luel-4013/deskweaver/internal/version"
)

// Schema is the stable plan schema identifier.
const Schema = "deskweaver.plan/v1"

// Options is the complete, non-interactive decision set.
type Options struct {
	ProjectPath    string
	Workspace      string
	Targets        []string
	Formats        []string
	Profile        string
	Sensitivity    string
	UntrustedInput bool
	Network        string
	Privilege      string
	OutputDir      string
	GenerateKit    bool
	Candidate      string
	Force          bool
	NoInput        bool
	Redact         bool
	Offline        bool
	MaxFiles       int
	HostOS         string
	ProbeTimeout   time.Duration
	Prefetched     *model.Project
	Now            func() time.Time
	OnProgress     func(Progress)
}

// Progress is a coarse, UI-friendly stage update.
type Progress struct {
	Stage   string
	Detail  string
	Percent int
}

// Result is the completed plan plus the kit location.
type Result struct {
	Plan       *model.Plan
	Project    *model.Project
	KitDir     string
	KitFiles   []string
	KitSkipped string
	Missing    []string
}

// ScanProject profiles a path without making any decisions. It is used by the
// interactive wizard to show evidence before asking adaptive questions.
func ScanProject(path, workspace string, maxFiles int) (*model.Project, error) {
	opts := scan.DefaultOptions()
	if maxFiles > 0 {
		opts.MaxFiles = maxFiles
	}
	opts.Workspace = workspace
	project, _, err := scan.Scan(path, opts)
	return project, err
}

// Run produces a complete plan and, when requested, an atomic review kit.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if strings.TrimSpace(opts.ProjectPath) == "" {
		return nil, fmt.Errorf("project path is required")
	}
	progress := func(stage, detail string, percent int) {
		if opts.OnProgress != nil {
			opts.OnProgress(Progress{Stage: stage, Detail: detail, Percent: percent})
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	root, err := filepath.Abs(opts.ProjectPath)
	if err != nil {
		return nil, fmt.Errorf("resolve project path: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve project path: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("project path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("project path is not a directory: %s", root)
	}

	progress("scan", "probing project files (read-only)", 10)
	project := opts.Prefetched
	if project == nil {
		project, err = ScanProject(root, opts.Workspace, opts.MaxFiles)
		if err != nil {
			return nil, err
		}
	}

	catalog, err := rules.Load()
	if err != nil {
		return nil, err
	}

	answers := normalizeAnswers(opts, root)
	progress("recommend", "scoring conversion technologies", 45)
	rec := recommend.Recommend(project, answers, recommend.Options{HostOS: hostOS(opts.HostOS)})

	requirements := []string(nil)
	if rec.Primary != nil {
		if candidate, ok := recommend.ByID(rec.Primary.ID); ok {
			requirements = doctor.FilterRequirements(candidate.Requires, answers.Targets)
		}
	}
	progress("doctor", "checking host dependencies (no installs)", 65)
	host := doctor.Check(requirements, doctor.Options{Timeout: opts.ProbeTimeout, Offline: opts.Offline})
	missing := doctor.MissingRequired(host)

	progress("security", "building threat-model controls", 80)
	sec := security.Build(project, rec, answers)

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	plan := &model.Plan{
		Schema:         Schema,
		ToolVersion:    version.Version,
		RulesVersion:   catalog.Version,
		RulesHash:      catalog.Hash(),
		GeneratedAt:    now().UTC().Format(time.RFC3339),
		Project:        *project,
		Answers:        answers,
		Host:           host,
		Recommendation: rec,
		Security:       sec,
	}
	if opts.Redact {
		redactPlan(plan)
	}

	var kitDir string
	var kitFiles []string
	skipped := ""
	if opts.GenerateKit {
		progress("kit", "rendering review-only kit", 90)
		plan.ArtifactManifest = kit.ManifestName
		plan.Artifacts = kit.PlannedFiles(*plan)
		plan.PlanHash = PlanHash(*plan)
		out := opts.OutputDir
		if strings.TrimSpace(out) == "" {
			out = defaultOutputDir(root)
		}
		if samePath(out, root) {
			return nil, fmt.Errorf("output directory must not be the project directory")
		}
		res, genErr := kit.Generate(ctx, *plan, kit.Options{OutputDir: out, Force: opts.Force})
		if genErr != nil {
			return nil, genErr
		}
		kitDir, kitFiles = res.Dir, res.Files
		if !kit.CanConvert(plan.Recommendation) {
			skipped = "The recommendation has blockers or no conversion path; only plan and security documents were generated."
		}
	} else {
		plan.PlanHash = PlanHash(*plan)
	}

	progress("done", "plan complete", 100)
	return &Result{
		Plan:       plan,
		Project:    project,
		KitDir:     kitDir,
		KitFiles:   kitFiles,
		KitSkipped: skipped,
		Missing:    missing,
	}, nil
}

// PlanHash returns a deterministic SHA-256 over the decision content. The
// timestamp, the hash itself, and host discovery noise are excluded so two
// runs with the same inputs on the same host can be compared.
func PlanHash(plan model.Plan) string {
	plan.GeneratedAt = ""
	plan.PlanHash = ""
	for i := range plan.Host.Tools {
		plan.Host.Tools[i].Path = ""
	}
	for i := range plan.Host.Webviews {
		plan.Host.Webviews[i].Path = ""
	}
	b, err := json.Marshal(plan)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func normalizeAnswers(opts Options, root string) model.Answers {
	targets := cleanList(opts.Targets)
	if len(targets) == 0 {
		targets = []string{"linux", "windows"}
	}
	formats := cleanList(opts.Formats)
	profile := strings.ToLower(strings.TrimSpace(opts.Profile))
	if profile == "" {
		profile = "hardened"
	}
	sensitivity := strings.ToLower(strings.TrimSpace(opts.Sensitivity))
	if sensitivity == "" {
		sensitivity = "internal"
	}
	network := strings.ToLower(strings.TrimSpace(opts.Network))
	if network == "" {
		if profile == "airgap" {
			network = "offline"
		} else {
			network = "offline"
		}
	}
	privilege := strings.ToLower(strings.TrimSpace(opts.Privilege))
	if privilege == "" {
		privilege = "none"
	}
	output := strings.TrimSpace(opts.OutputDir)
	if output == "" && opts.GenerateKit {
		output = defaultOutputDir(root)
	}
	if output != "" {
		if abs, err := filepath.Abs(output); err == nil {
			output = abs
		}
	}
	return model.Answers{
		ProjectPath:    root,
		Workspace:      cleanPath(opts.Workspace),
		Targets:        targets,
		Formats:        formats,
		Profile:        profile,
		Sensitivity:    sensitivity,
		UntrustedInput: opts.UntrustedInput,
		Network:        network,
		Privilege:      privilege,
		OutputDir:      output,
		GenerateKit:    opts.GenerateKit,
		Candidate:      strings.TrimSpace(opts.Candidate),
		Force:          opts.Force,
		NoInput:        opts.NoInput,
		Redact:         opts.Redact,
		Offline:        opts.Offline,
	}
}

func defaultOutputDir(projectRoot string) string {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = filepath.Dir(projectRoot)
	}
	dir := filepath.Join(cwd, "deskweaver-out")
	if isInside(dir, projectRoot) {
		dir = filepath.Join(filepath.Dir(projectRoot), "deskweaver-out")
	}
	return dir
}

func isInside(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func samePath(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return filepath.Clean(aa) == filepath.Clean(bb)
}

func redactPlan(plan *model.Plan) {
	home, _ := os.UserHomeDir()
	plan.Project.Root = "."
	plan.Answers.ProjectPath = "."
	plan.Answers.OutputDir = ""
	for i := range plan.Host.Tools {
		if plan.Host.Tools[i].Path != "" {
			plan.Host.Tools[i].Path = filepath.Base(plan.Host.Tools[i].Path)
		}
	}
	for i := range plan.Host.Webviews {
		plan.Host.Webviews[i].Path = ""
	}
	for i := range plan.Host.Checks {
		plan.Host.Checks[i].Detail = redactText(plan.Host.Checks[i].Detail, home)
		plan.Host.Checks[i].Install = redactText(plan.Host.Checks[i].Install, home)
	}
	for i := range plan.Host.Warnings {
		plan.Host.Warnings[i] = redactText(plan.Host.Warnings[i], home)
	}
	if home != "" {
		b, _ := json.Marshal(plan)
		out := strings.ReplaceAll(string(b), home, "~")
		_ = json.Unmarshal([]byte(out), plan)
	}
}

func redactText(s, home string) string {
	if home == "" {
		return s
	}
	return strings.ReplaceAll(s, home, "~")
}

func hostOS(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return strings.ToLower(strings.TrimSpace(explicit))
	}
	return runtime.GOOS
}

func cleanList(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range in {
		for _, part := range strings.Split(v, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

func cleanPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "." {
		return ""
	}
	return filepath.ToSlash(p)
}
