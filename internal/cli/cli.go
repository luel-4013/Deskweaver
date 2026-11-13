package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/luel-4013/deskweaver/internal/app"
	"github.com/luel-4013/deskweaver/internal/kit"
	"github.com/luel-4013/deskweaver/internal/model"
	"github.com/luel-4013/deskweaver/internal/ui"
	"github.com/luel-4013/deskweaver/internal/version"
	"github.com/mattn/go-isatty"
)

// Exit codes. They are part of the CLI contract.
const (
	exitOK          = 0
	exitUsage       = 1
	exitBlockers    = 2
	exitMissingDeps = 3
	exitUnsupported = 4
	exitInternal    = 5
	exitCancelled   = 130
)

type cliError struct {
	code int
	msg  string
}

func (e *cliError) Error() string { return e.msg }

func failf(code int, format string, args ...any) error {
	return &cliError{code: code, msg: fmt.Sprintf(format, args...)}
}

type streams struct {
	in      io.Reader
	out     io.Writer
	err     io.Writer
	json    bool
	noColor bool
}

func (s *streams) printf(format string, args ...any) {
	fmt.Fprintf(s.out, format, args...)
}

func (s *streams) errorf(format string, args ...any) {
	fmt.Fprintf(s.err, format, args...)
}

func (s *streams) encode(v any) error {
	enc := json.NewEncoder(s.out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Run executes the CLI with the process streams. It returns the process exit
// code; generated artifacts are committed atomically before a non-zero result
// is reported.
func Run(args []string) int {
	return RunContext(context.Background(), args, os.Stdin, os.Stdout, os.Stderr)
}

// RunContext is the testable entry point.
func RunContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	inv, err := parse(args)
	if err != nil {
		s := &streams{in: stdin, out: stdout, err: stderr}
		emitError(s, exitUsage, err)
		return exitUsage
	}
	jsonMode, err := inv.bool("json")
	if err != nil {
		s := &streams{in: stdin, out: stdout, err: stderr}
		emitError(s, exitUsage, err)
		return exitUsage
	}
	noColor, _ := inv.bool("no-color")
	s := &streams{in: stdin, out: stdout, err: stderr, json: jsonMode, noColor: noColor}

	if inv.has("version") || inv.command == "version" {
		code, err := printVersion(s, inv)
		return finish(s, code, err)
	}
	if inv.has("help") || inv.command == "help" {
		s.printf("%s", helpText)
		return exitOK
	}
	if inv.command == "" {
		if hasPlanChoiceFlags(inv) {
			emitError(s, exitUsage, errors.New("a command is required when plan flags are present (try: deskweaver plan --no-input .)"))
			return exitUsage
		}
		if !interactive(stdin, stdout) {
			emitError(s, exitUsage, errors.New("the wizard needs an interactive terminal; run deskweaver scan/plan with a path, --answers, or --no-input"))
			return exitUsage
		}
		code, err := cmdWizard(ctx, inv, s)
		return finish(s, code, err)
	}

	var code int
	switch inv.command {
	case "plan":
		code, err = cmdPlan(ctx, inv, s)
	case "scan":
		code, err = cmdScan(ctx, inv, s)
	case "bundle":
		code, err = cmdBundle(ctx, inv, s)
	case "doctor":
		code, err = cmdDoctor(ctx, inv, s)
	case "targets":
		code, err = cmdTargets(ctx, inv, s)
	case "explain":
		code, err = cmdExplain(ctx, inv, s)
	case "rules":
		code, err = cmdRules(ctx, inv, s)
	case "self-check":
		code, err = cmdSelfCheck(ctx, inv, s)
	default:
		err = failf(exitUsage, "unknown command %q (run deskweaver --help)", inv.command)
	}
	return finish(s, code, err)
}

func finish(s *streams, code int, err error) int {
	if err == nil {
		return code
	}
	code = codeFor(err)
	if errors.Is(err, context.Canceled) || errors.Is(err, ui.ErrCancelled) {
		code = exitCancelled
		if !s.json {
			s.errorf("deskweaver: cancelled; no partial output was committed\n")
		} else {
			emitError(s, code, errors.New("cancelled; no partial output was committed"))
		}
		return code
	}
	emitError(s, code, err)
	return code
}

func codeFor(err error) int {
	var ce *cliError
	if errors.As(err, &ce) {
		return ce.code
	}
	if errors.Is(err, context.Canceled) {
		return exitCancelled
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "project path"), strings.Contains(msg, "workspace"),
		strings.Contains(msg, "output"), strings.Contains(msg, "refusing"),
		strings.Contains(msg, "answers"), strings.Contains(msg, "plan file"),
		strings.Contains(msg, "not a directory"), strings.Contains(msg, "does not exist"):
		return exitUsage
	default:
		return exitInternal
	}
}

func emitError(s *streams, code int, err error) {
	msg := safeText(err.Error())
	if s.json {
		_ = json.NewEncoder(s.err).Encode(struct {
			Schema   string `json:"schema"`
			Error    string `json:"error"`
			ExitCode int    `json:"exit_code"`
		}{Schema: "deskweaver.error/v1", Error: msg, ExitCode: code})
		return
	}
	fmt.Fprintf(s.err, "deskweaver: %s\n", msg)
}

func cmdWizard(ctx context.Context, inv *invocation, s *streams) (int, error) {
	if len(inv.args) > 1 {
		return exitUsage, failf(exitUsage, "too many arguments for the wizard")
	}
	start := ""
	if len(inv.args) == 1 {
		start = inv.args[0]
	}
	maxFiles, err := inv.int("max-files")
	if err != nil {
		return exitUsage, failf(exitUsage, "%v", err)
	}
	if inv.has("max-files") && !validMaxFiles(maxFiles) {
		return exitUsage, failf(exitUsage, "--max-files must be between 1 and 1000000")
	}
	opts, err := ui.Run(ctx, ui.Options{
		StartPath: start,
		In:        s.in,
		Out:       s.out,
		MaxFiles:  maxFiles,
		NoColor:   s.noColor,
	})
	if err != nil {
		if errors.Is(err, ui.ErrCancelled) || errors.Is(err, context.Canceled) {
			return exitCancelled, context.Canceled
		}
		return exitInternal, err
	}
	if v, _ := inv.bool("redact"); v {
		opts.Redact = true
	}
	if v, _ := inv.bool("offline"); v {
		opts.Offline = true
	}
	res, err := app.Run(ctx, opts)
	if err != nil {
		return exitInternal, err
	}
	return reportPlan(s, res)
}

func cmdPlan(ctx context.Context, inv *invocation, s *streams) (int, error) {
	if len(inv.args) > 1 {
		return exitUsage, failf(exitUsage, "plan accepts at most one project path")
	}
	pathArg := ""
	if len(inv.args) == 1 {
		pathArg = inv.args[0]
	}
	a, err := maybeLoadAnswers(inv)
	if err != nil {
		return exitUsage, err
	}
	if shouldWizard(inv, s) {
		if pathArg != "" {
			inv.args = []string{pathArg}
		}
		return cmdWizard(ctx, inv, s)
	}
	if a == nil && !inv.has("no-input") && !s.json {
		return exitUsage, errors.New("plan needs an interactive terminal, --answers, or --no-input; it will not guess in a non-interactive session")
	}
	opts, err := planOptions(inv, a, pathArg, s.json)
	if err != nil {
		return exitUsage, err
	}
	if !s.json {
		opts.OnProgress = func(p app.Progress) {
			if p.Detail != "" {
				fmt.Fprintf(s.err, "  [%3d%%] %s\n", p.Percent, p.Detail)
			}
		}
	}
	res, err := app.Run(ctx, opts)
	if err != nil {
		return exitInternal, err
	}
	return reportPlan(s, res)
}

func reportPlan(s *streams, res *app.Result) (int, error) {
	if s.json {
		if err := s.encode(res.Plan); err != nil {
			return exitInternal, err
		}
	} else {
		printPlan(s.out, res)
	}
	return planExitCode(res.Plan, res.Missing), nil
}

func planExitCode(plan *model.Plan, missing []string) int {
	if plan == nil {
		return exitInternal
	}
	if plan.Recommendation.ManualReview || len(plan.Recommendation.Blockers) > 0 {
		return exitBlockers
	}
	if len(missing) > 0 {
		return exitMissingDeps
	}
	return exitOK
}

func cmdScan(ctx context.Context, inv *invocation, s *streams) (int, error) {
	if len(inv.args) > 1 {
		return exitUsage, failf(exitUsage, "scan accepts at most one project path")
	}
	path := ""
	if len(inv.args) == 1 {
		path = inv.args[0]
	}
	a, err := maybeLoadAnswers(inv)
	if err != nil {
		return exitUsage, err
	}
	if path == "" && a != nil {
		path = a.ProjectPath
	}
	if path == "" {
		path = "."
	}
	workspace := inv.one("workspace")
	if workspace == "" && a != nil {
		workspace = a.Workspace
	}
	maxFiles, err := inv.int("max-files")
	if err != nil {
		return exitUsage, failf(exitUsage, "%v", err)
	}
	if inv.has("max-files") && !validMaxFiles(maxFiles) {
		return exitUsage, failf(exitUsage, "--max-files must be between 1 and 1000000")
	}
	if err := ctx.Err(); err != nil {
		return exitCancelled, err
	}
	project, err := app.ScanProject(path, workspace, maxFiles)
	if err != nil {
		return exitUsage, err
	}
	if s.json {
		if err := s.encode(project); err != nil {
			return exitInternal, err
		}
	} else {
		printProject(s.out, project)
	}
	if project.Primary == nil {
		return exitBlockers, nil
	}
	return exitOK, nil
}

func cmdBundle(ctx context.Context, inv *invocation, s *streams) (int, error) {
	if len(inv.args) > 1 {
		return exitUsage, failf(exitUsage, "bundle accepts at most one plan path")
	}
	if len(inv.args) == 0 && inv.one("out") == "" {
		// No path: use the default kit location if it exists, otherwise fail
		// with an explicit instruction. Never search the filesystem.
		candidate := filepath.Join("deskweaver-out", "plan.json")
		if _, err := os.Stat(candidate); err == nil {
			inv.args = []string{candidate}
		}
	}
	if len(inv.args) == 0 {
		return exitUsage, errors.New("bundle requires a plan.json path")
	}
	planPath := inv.args[0]
	if st, err := os.Stat(planPath); err == nil && st.IsDir() {
		planPath = filepath.Join(planPath, "plan.json")
	}
	plan, err := readPlan(planPath)
	if err != nil {
		return exitUsage, err
	}
	plan.Artifacts = kit.PlannedFiles(*plan)
	plan.ArtifactManifest = kit.ManifestName
	plan.Answers.GenerateKit = true
	plan.PlanHash = app.PlanHash(*plan)

	out := strings.TrimSpace(inv.one("out"))
	if out == "" {
		out = plan.Answers.OutputDir
	}
	if out == "" {
		out = defaultKitOutput(plan.Project.Root)
	} else if !filepath.IsAbs(out) {
		// A stored output path is relative to the plan file; an explicit --out
		// is relative to the caller's working directory.
		if inv.one("out") == "" {
			out = filepath.Join(filepath.Dir(planPath), out)
		}
	}
	if samePath(out, plan.Project.Root) && plan.Project.Root != "" && plan.Project.Root != "." {
		return exitUsage, errors.New("output directory must not be the project directory")
	}
	force, ferr := inv.bool("force")
	if ferr != nil {
		return exitUsage, ferr
	}
	res, err := kit.Generate(ctx, *plan, kit.Options{OutputDir: out, Force: force})
	if err != nil {
		return exitUsage, err
	}
	if s.json {
		if err := s.encode(struct {
			Schema   string   `json:"schema"`
			PlanHash string   `json:"plan_hash"`
			KitDir   string   `json:"kit_dir"`
			Files    []string `json:"files"`
			Blockers []string `json:"blockers,omitempty"`
			ExitCode int      `json:"exit_code"`
		}{
			Schema: "deskweaver.bundle/v1", PlanHash: plan.PlanHash, KitDir: res.Dir,
			Files: res.Files, Blockers: plan.Recommendation.Blockers,
			ExitCode: planExitCode(plan, nil),
		}); err != nil {
			return exitInternal, err
		}
	} else {
		s.printf("Deskweaver kit regenerated\n")
		s.printf("  Plan:   %s\n", planPath)
		s.printf("  Output: %s\n", res.Dir)
		s.printf("  Files:  %d\n", len(res.Files))
		s.printf("  Hash:   %s\n", plan.PlanHash)
		if res.BackupDir != "" {
			s.printf("  Backup: %s\n", res.BackupDir)
		}
		if len(plan.Recommendation.Blockers) > 0 || plan.Recommendation.ManualReview {
			s.printf("\n  Blockers remain; conversion files were not generated.\n")
			for _, b := range plan.Recommendation.Blockers {
				s.printf("  - %s\n", safeText(b))
			}
		}
	}
	return planExitCode(plan, nil), nil
}

func hasPlanChoiceFlags(inv *invocation) bool {
	for _, name := range []string{
		"answers", "no-input", "target", "format", "profile", "sensitivity",
		"untrusted-input", "network", "privilege", "out", "weight",
		"candidate", "workspace", "no-kit", "force", "redact",
	} {
		if inv.has(name) {
			return true
		}
	}
	return false
}

func shouldWizard(inv *invocation, s *streams) bool {
	if s.json || inv.has("answers") || inv.has("no-input") {
		return false
	}
	for _, name := range []string{
		"target", "format", "profile", "sensitivity", "untrusted-input",
		"network", "privilege", "out", "weight", "candidate", "workspace",
		"no-kit", "force",
	} {
		if inv.has(name) {
			return false
		}
	}
	return interactive(s.in, s.out)
}

func maybeLoadAnswers(inv *invocation) (*model.Answers, error) {
	if !inv.has("answers") {
		return nil, nil
	}
	a, err := loadAnswers(inv.one("answers"))
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func planOptions(inv *invocation, a *model.Answers, pathArg string, jsonMode bool) (app.Options, error) {
	if inv.has("weight") {
		return app.Options{}, failf(exitUsage, "--weight is reserved but candidate weighting is not implemented in this build; remove it rather than having it silently ignored")
	}
	opts := app.Options{GenerateKit: true, NoInput: true}
	if a != nil {
		opts.ProjectPath = a.ProjectPath
		opts.Workspace = a.Workspace
		opts.Targets = append([]string(nil), a.Targets...)
		opts.Formats = append([]string(nil), a.Formats...)
		opts.Profile = a.Profile
		opts.Sensitivity = a.Sensitivity
		opts.UntrustedInput = a.UntrustedInput
		opts.Network = a.Network
		opts.Privilege = a.Privilege
		opts.OutputDir = a.OutputDir
		opts.GenerateKit = a.GenerateKit
		opts.Candidate = a.Candidate
	}
	if pathArg != "" {
		opts.ProjectPath = pathArg
	}
	if opts.ProjectPath == "" {
		if !inv.has("no-input") {
			return app.Options{}, failf(exitUsage, "project path is required (pass a path or --answers)")
		}
		opts.ProjectPath = "."
	}
	if inv.has("workspace") {
		opts.Workspace = inv.one("workspace")
	}
	if inv.has("target") {
		opts.Targets = cleanValues(inv.values["target"])
	}
	if len(opts.Targets) == 0 {
		opts.Targets = []string{"linux", "windows"}
	}
	targets, err := validateTargets(opts.Targets)
	if err != nil {
		return app.Options{}, err
	}
	opts.Targets = targets

	if inv.has("format") {
		opts.Formats = cleanValues(inv.values["format"])
	}
	if len(opts.Formats) == 0 {
		opts.Formats = defaultFormats(targets)
	}
	formats, err := validateFormats(opts.Formats, targets)
	if err != nil {
		return app.Options{}, err
	}
	opts.Formats = formats

	if inv.has("profile") {
		opts.Profile = strings.ToLower(strings.TrimSpace(inv.one("profile")))
	}
	if opts.Profile == "" {
		opts.Profile = "hardened"
	}
	if err := validateEnum("profile", opts.Profile, []string{"baseline", "hardened", "airgap", "hostile-input", "privileged-service"}); err != nil {
		return app.Options{}, err
	}
	if inv.has("sensitivity") {
		opts.Sensitivity = strings.ToLower(strings.TrimSpace(inv.one("sensitivity")))
	}
	if opts.Sensitivity == "" {
		opts.Sensitivity = "internal"
	}
	if err := validateEnum("sensitivity", opts.Sensitivity, []string{"public", "internal", "confidential", "regulated"}); err != nil {
		return app.Options{}, err
	}
	if inv.has("untrusted-input") {
		v, err := inv.bool("untrusted-input")
		if err != nil {
			return app.Options{}, failf(exitUsage, "%v", err)
		}
		opts.UntrustedInput = v
	}
	if inv.has("network") {
		opts.Network = strings.ToLower(strings.TrimSpace(inv.one("network")))
	}
	if opts.Network == "" {
		opts.Network = "offline"
	}
	if err := validateEnum("network", opts.Network, []string{"offline", "allowlist", "open"}); err != nil {
		return app.Options{}, err
	}
	if inv.has("privilege") {
		opts.Privilege = strings.ToLower(strings.TrimSpace(inv.one("privilege")))
	}
	if opts.Privilege == "" {
		opts.Privilege = "none"
	}
	if err := validateEnum("privilege", opts.Privilege, []string{"none", "raw-sockets", "usb", "privileged-service", "kernel"}); err != nil {
		return app.Options{}, err
	}
	if inv.has("candidate") {
		opts.Candidate = strings.ToLower(strings.TrimSpace(inv.one("candidate")))
	}
	if inv.has("out") {
		opts.OutputDir = inv.one("out")
	}
	if opts.GenerateKit && opts.OutputDir != "" && samePath(opts.OutputDir, opts.ProjectPath) {
		return app.Options{}, failf(exitUsage, "output directory must not be the project directory")
	}
	if inv.has("no-kit") {
		v, err := inv.bool("no-kit")
		if err != nil {
			return app.Options{}, failf(exitUsage, "%v", err)
		}
		if v && inv.has("out") {
			return app.Options{}, failf(exitUsage, "--no-kit and --out cannot be combined")
		}
		opts.GenerateKit = !v
	}
	if inv.has("out") {
		opts.GenerateKit = true
	}
	force, err := inv.bool("force")
	if err != nil {
		return app.Options{}, failf(exitUsage, "%v", err)
	}
	opts.Force = force
	if v, _ := inv.bool("redact"); v {
		opts.Redact = true
	}
	if v, _ := inv.bool("offline"); v {
		opts.Offline = true
	}
	opts.NoInput = inv.has("no-input") || a != nil || jsonMode
	maxFiles, err := inv.int("max-files")
	if err != nil {
		return app.Options{}, failf(exitUsage, "%v", err)
	}
	if inv.has("max-files") && !validMaxFiles(maxFiles) {
		return app.Options{}, failf(exitUsage, "--max-files must be between 1 and 1000000")
	}
	opts.MaxFiles = maxFiles
	return opts, nil
}

func validateTargets(in []string) ([]string, error) {
	valid := map[string]bool{"linux": true, "windows": true, "macos": true, "android": true, "ios": true}
	var out []string
	for _, t := range cleanValues(in) {
		if !valid[t] {
			return nil, failf(exitUnsupported, "unsupported target %q; supported targets: linux, windows, macos, android, ios", t)
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, failf(exitUsage, "at least one target is required")
	}
	return out, nil
}

func validateFormats(in, targets []string) ([]string, error) {
	formatOS := map[string]string{
		"flatpak": "linux", "appimage": "linux", "deb": "linux", "rpm": "linux",
		"tarball": "linux", "snap": "linux",
		"nsis": "windows", "msi": "windows", "portable": "windows", "msix": "windows",
		"dmg": "macos", "app": "macos", "pkg": "macos",
		"apk": "android", "aab": "android", "ipa": "ios",
	}
	targetSet := map[string]bool{}
	for _, t := range targets {
		targetSet[t] = true
	}
	var out []string
	for _, f := range cleanValues(in) {
		osName, ok := formatOS[f]
		if !ok {
			return nil, failf(exitUsage, "unknown distribution format %q", f)
		}
		if !targetSet[osName] {
			return nil, failf(exitUnsupported, "format %q is not valid for the selected targets", f)
		}
		out = append(out, f)
	}
	return out, nil
}

func defaultFormats(targets []string) []string {
	var out []string
	for _, t := range targets {
		switch t {
		case "linux":
			out = append(out, "flatpak", "appimage", "deb")
		case "windows":
			out = append(out, "nsis", "portable")
		case "macos":
			out = append(out, "dmg")
		case "android":
			out = append(out, "apk")
		case "ios":
			out = append(out, "ipa")
		}
	}
	return out
}

func validateEnum(name, value string, allowed []string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return failf(exitUsage, "invalid --%s %q; allowed: %s", name, value, strings.Join(allowed, ", "))
}

func validMaxFiles(n int) bool { return n >= 1 && n <= 1000000 }

func interactive(in io.Reader, out io.Writer) bool {
	inFile, okIn := in.(*os.File)
	outFile, okOut := out.(*os.File)
	if !okIn || !okOut {
		return false
	}
	return isTerminal(inFile) && isTerminal(outFile)
}

func isTerminal(f *os.File) bool {
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}

func defaultKitOutput(projectRoot string) string {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	dir := filepath.Join(cwd, "deskweaver-out")
	if projectRoot != "" && projectRoot != "." && isInside(dir, projectRoot) {
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
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return filepath.Clean(aa) == filepath.Clean(bb)
}

type versionInfo struct {
	Schema    string `json:"schema"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func printVersion(s *streams, inv *invocation) (int, error) {
	info := versionInfo{
		Schema: "deskweaver.version/v1", Version: version.Version,
		Commit: version.Commit, BuildDate: version.BuildDate,
		OS: runtime.GOOS, Arch: runtime.GOARCH,
	}
	if s.json {
		if err := s.encode(info); err != nil {
			return exitInternal, err
		}
		return exitOK, nil
	}
	s.printf("Deskweaver %s\n", version.String())
	s.printf("Advisor-only: no installs, no project writes, no project-code execution.\n")
	return exitOK, nil
}
