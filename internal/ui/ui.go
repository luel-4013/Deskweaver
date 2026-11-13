// Package ui implements the interactive, adaptive wizard.
//
// The wizard only collects decisions. Scanning is read-only and kit generation
// happens later through internal/app, after the form has completed.
package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/luel-4013/deskweaver/internal/app"
	"github.com/luel-4013/deskweaver/internal/model"
	"github.com/luel-4013/deskweaver/internal/recommend"
	"github.com/mattn/go-isatty"
)

// ErrCancelled is returned when the user exits the wizard without submitting.
var ErrCancelled = errors.New("wizard cancelled")

// Options configures the wizard.
type Options struct {
	StartPath string
	In        io.Reader
	Out       io.Writer
	MaxFiles  int
	NoColor   bool
}

// Run asks the adaptive question set and returns a complete app option set.
func Run(ctx context.Context, opts Options) (app.Options, error) {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	if err := ensureInteractive(opts); err != nil {
		return app.Options{}, err
	}
	banner(out, opts.NoColor)

	project, path, workspace, err := resolveProject(ctx, opts, out)
	if err != nil {
		return app.Options{}, err
	}

	answers, err := askDecisions(ctx, opts, out, project)
	if err != nil {
		return app.Options{}, err
	}

	prefetched := project
	if !answers.acceptDetection && prefetched.Primary != nil {
		copyProject := *prefetched
		copyProject.Primary = nil
		copyProject.Capabilities = []string{"unknown"}
		copyProject.Unknowns = append(copyProject.Unknowns,
			"Automatic detection was rejected in the wizard; complete a manual profile before conversion.")
		prefetched = &copyProject
	}

	return app.Options{
		ProjectPath:    path,
		Workspace:      workspace,
		Targets:        answers.targets,
		Formats:        sanitizeFormats(answers.formats, answers.targets),
		Profile:        answers.profile,
		Sensitivity:    answers.sensitivity,
		UntrustedInput: answers.untrusted,
		Network:        answers.network,
		Privilege:      answers.privilege,
		OutputDir:      strings.TrimSpace(answers.outputDir),
		GenerateKit:    answers.generateKit,
		Candidate:      answers.candidate,
		NoInput:        false,
		MaxFiles:       opts.MaxFiles,
		Prefetched:     prefetched,
		OnProgress:     progressPrinter(out),
	}, nil
}

// IsInteractive reports whether both standard streams are terminals.
func IsInteractive() bool {
	return isTerminal(os.Stdin) && isTerminal(os.Stdout)
}

func isTerminal(f *os.File) bool {
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}

func ensureInteractive(opts Options) error {
	if opts.In != nil && opts.Out != nil {
		return nil
	}
	if IsInteractive() {
		return nil
	}
	return fmt.Errorf("the wizard needs an interactive terminal; pass a path, --answers, or --no-input")
}

func banner(w io.Writer, noColor bool) {
	title := "Deskweaver — conversion advisor"
	if !noColor {
		title = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render(title)
	}
	fmt.Fprintf(w, "%s\n", title)
	fmt.Fprintln(w, "Read-only scan. No installs, no project writes, no project-code execution.")
	fmt.Fprintln(w, "Adaptive questions: only what can change the plan. Ctrl-C cancels without writing.")
	fmt.Fprintln(w)
}

func resolveProject(ctx context.Context, opts Options, out io.Writer) (*model.Project, string, string, error) {
	path := strings.TrimSpace(opts.StartPath)
	workspace := ""
	for attempts := 0; attempts < 8; attempts++ {
		if path == "" {
			var err error
			path, err = promptPath(ctx, opts, out, defaultStartPath())
			if err != nil {
				return nil, "", "", err
			}
		}
		fmt.Fprintf(out, "Scanning %s (read-only)...\n", path)
		project, err := app.ScanProject(path, workspace, opts.MaxFiles)
		if err != nil {
			fmt.Fprintf(out, "Cannot scan: %v\n\n", err)
			path = ""
			workspace = ""
			continue
		}
		if project.Monorepo {
			workspace, err = chooseWorkspace(ctx, opts, out, project)
			if err != nil {
				return nil, "", "", err
			}
			if workspace != "" {
				fmt.Fprintf(out, "Scanning workspace %s (read-only)...\n", workspace)
				project, err = app.ScanProject(path, workspace, opts.MaxFiles)
				if err != nil {
					fmt.Fprintf(out, "Cannot scan workspace: %v\n\n", err)
					workspace = ""
					continue
				}
			}
		}
		if project.Primary != nil {
			printSummary(out, project)
			return project, path, workspace, nil
		}
		printSummary(out, project)
		choice, err := promptNoDetection(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		switch choice {
		case "parent":
			parent := filepath.Dir(path)
			if parent == path {
				fmt.Fprintln(out, "Already at the filesystem root; choose another directory.")
				continue
			}
			path, workspace = parent, ""
		case "another":
			path, workspace = "", ""
		default:
			return project, path, workspace, nil
		}
	}
	return nil, "", "", fmt.Errorf("too many scan attempts; pass a known project path with --no-input")
}

func promptPath(ctx context.Context, opts Options, out io.Writer, initial string) (string, error) {
	value := initial
	field := huh.NewInput().
		Title("Path to the project directory?").
		Description("Type, paste, or drag a path. The scan is read-only and never executes project code.").
		Placeholder(defaultPlaceholder()).
		Value(&value).
		SuggestionsFunc(func() []string { return dirSuggestions(value) }, &value).
		Validate(validateDir)

	form := newForm(opts, huh.NewGroup(field).Title("Step 1 · Project"))
	if err := form.RunWithContext(ctx); err != nil {
		return "", mapCancel(err)
	}
	return expandPath(value)
}

func chooseWorkspace(ctx context.Context, opts Options, out io.Writer, project *model.Project) (string, error) {
	if len(project.Workspaces) > 0 {
		choice := "root"
		options := []huh.Option[string]{
			huh.NewOption("Repository root (explicit choice)", "root"),
		}
		for _, ws := range project.Workspaces {
			options = append(options, huh.NewOption(ws, ws))
		}
		field := huh.NewSelect[string]().
			Title("Which workspace should Deskweaver analyze?").
			Description("A monorepo was detected. Deskweaver never silently picks one.").
			Options(options...).
			Value(&choice)
		form := newForm(opts, huh.NewGroup(field).Title("Workspace selection"))
		if err := form.RunWithContext(ctx); err != nil {
			return "", mapCancel(err)
		}
		if choice == "root" {
			return "", nil
		}
		return choice, nil
	}

	var ws string
	field := huh.NewInput().
		Title("Workspace path (relative to the project root)").
		Description("No workspace packages were detected. Leave blank to analyze the repository root, or enter a path such as apps/web.").
		Value(&ws)
	form := newForm(opts, huh.NewGroup(field).Title("Workspace selection"))
	if err := form.RunWithContext(ctx); err != nil {
		return "", mapCancel(err)
	}
	ws = strings.TrimSpace(ws)
	if ws == "." {
		return "", nil
	}
	return ws, nil
}

func promptNoDetection(ctx context.Context, opts Options) (string, error) {
	choice := "manual"
	field := huh.NewSelect[string]().
		Title("No known framework matched.").
		Description("Choose a next step. Deskweaver will not guess a conversion target from unknown evidence.").
		Options(
			huh.NewOption("Continue with a manual profile (recommended)", "manual"),
			huh.NewOption("Scan the parent directory", "parent"),
			huh.NewOption("Choose another directory", "another"),
		).
		Value(&choice)
	form := newForm(opts, huh.NewGroup(field).Title("Manual review"))
	if err := form.RunWithContext(ctx); err != nil {
		return "", mapCancel(err)
	}
	return choice, nil
}

type decisionAnswers struct {
	acceptDetection bool
	targets         []string
	formats         []string
	profile         string
	sensitivity     string
	untrusted       bool
	network         string
	privilege       string
	generateKit     bool
	outputDir       string
	customize       bool
	candidate       string
}

func askDecisions(ctx context.Context, opts Options, out io.Writer, project *model.Project) (decisionAnswers, error) {
	answers := decisionAnswers{
		acceptDetection: true,
		targets:         defaultTargets(),
		profile:         "hardened",
		sensitivity:     "internal",
		network:         "offline",
		privilege:       "none",
		generateKit:     true,
	}
	answers.formats = defaultFormats(answers.targets)

	groups := []*huh.Group{
		detectionGroup(project, &answers),
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Which operating systems must this app support?").
				Description("Linux and Windows are Tier 1. macOS is Tier 2. Android/iOS are separate delivery plans, not desktop parity.").
				Options(
					huh.NewOption("Linux (Tier 1)", "linux"),
					huh.NewOption("Windows (Tier 1)", "windows"),
					huh.NewOption("macOS (Tier 2)", "macos"),
					huh.NewOption("Android (Tier 3, separate plan)", "android"),
					huh.NewOption("iOS (Tier 3, requires macOS to build)", "ios"),
				).
				Value(&answers.targets).
				Validate(func(v []string) error {
					if len(v) == 0 {
						return errors.New("choose at least one target")
					}
					return nil
				}),
			huh.NewMultiSelect[string]().
				Title("Distribution formats").
				Description("Only formats for the selected targets are shown. These are review targets, not builds.").
				OptionsFunc(func() []huh.Option[string] {
					return formatOptions(answers.targets)
				}, &answers.targets).
				Value(&answers.formats).
				Validate(func(v []string) error {
					if !hasDesktop(answers.targets) {
						return nil
					}
					if len(v) == 0 {
						return errors.New("choose at least one desktop format")
					}
					allowed := map[string]bool{}
					for _, o := range formatOptions(answers.targets) {
						allowed[o.Value] = true
					}
					for _, f := range v {
						if !allowed[f] {
							return fmt.Errorf("%s is not valid for the selected targets", f)
						}
					}
					return nil
				}),
		).Title("Targets and formats"),

		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Security profile").
				Description("Hardened is the default for sensitive or paranoid work. Profiles combine; conflicts are reported, not hidden.").
				Options(
					huh.NewOption("Hardened (recommended)", "hardened"),
					huh.NewOption("Baseline (internal app, trusted input)", "baseline"),
					huh.NewOption("Airgap (offline/isolated)", "airgap"),
					huh.NewOption("Hostile input (malware/arbitrary parsers)", "hostile-input"),
					huh.NewOption("Privileged service (capture/USB/raw sockets)", "privileged-service"),
				).
				Value(&answers.profile),
			huh.NewSelect[string]().
				Title("Data sensitivity").
				Description("Higher sensitivity enables data-at-rest and logging controls.").
				Options(
					huh.NewOption("Internal", "internal"),
					huh.NewOption("Public", "public"),
					huh.NewOption("Confidential", "confidential"),
					huh.NewOption("Regulated (health, finance, legal)", "regulated"),
				).
				Value(&answers.sensitivity),
			huh.NewConfirm().
				Title("Does the app process untrusted or hostile input?").
				Description("Examples: arbitrary uploads, parser targets, malware samples. Hostile input changes the engine and isolation recommendation.").
				Value(&answers.untrusted).
				Affirmative("Yes, treat input as hostile").
				Negative("No, input is trusted"),
		).Title("Threat model"),

		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Network exposure").
				Description("Offline is the safest default. Open network access is a deliberate risk, not a default.").
				Options(
					huh.NewOption("Offline / airgapped (recommended)", "offline"),
					huh.NewOption("Egress allowlist only", "allowlist"),
					huh.NewOption("Open network access", "open"),
				).
				Value(&answers.network),
			huh.NewSelect[string]().
				Title("Privilege requirement").
				Description("Never run the GUI as root. Privileged capture belongs in a separate service.").
				Options(
					huh.NewOption("None (recommended)", "none"),
					huh.NewOption("Raw sockets / packet capture", "raw-sockets"),
					huh.NewOption("USB or serial device access", "usb"),
					huh.NewOption("Root/admin helper service", "privileged-service"),
					huh.NewOption("Kernel module / driver", "kernel"),
				).
				Value(&answers.privilege),
		).Title("Exposure and privilege"),

		huh.NewGroup(
			huh.NewConfirm().
				Title("Generate the review-only conversion kit?").
				Description("The kit contains a plan, security templates, and read-only preflight scripts. Nothing is executed or applied.").
				Value(&answers.generateKit).
				Affirmative("Yes, generate the kit").
				Negative("No, show the plan only"),
		).Title("Output"),

		huh.NewGroup(
			huh.NewInput().
				Title("Output directory").
				Description("Default is deskweaver-out outside the project. Existing non-empty directories are refused unless you pass --force.").
				Placeholder("deskweaver-out (default)").
				Value(&answers.outputDir),
		).Title("Output directory").WithHideFunc(func() bool { return !answers.generateKit }),

		huh.NewGroup(
			huh.NewConfirm().
				Title("Customize the technology recommendation?").
				Description("Advanced: override Deskweaver's ranked choice. The score and risks are still shown.").
				Value(&answers.customize).
				Affirmative("Yes, choose a technology").
				Negative("No, use the recommendation"),
		).Title("Advanced"),

		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Technology override").
				Description("An override wins only if it supports every requested target. Deskweaver still reports the trade-offs.").
				Options(candidateOptions(project)...).
				Value(&answers.candidate),
		).Title("Technology override").WithHideFunc(func() bool { return !answers.customize }),
	}

	form := newForm(opts, groups...)
	if err := form.RunWithContext(ctx); err != nil {
		return answers, mapCancel(err)
	}
	if len(answers.targets) == 0 {
		answers.targets = defaultTargets()
	}
	answers.formats = sanitizeFormats(answers.formats, answers.targets)
	return answers, nil
}

func detectionGroup(project *model.Project, answers *decisionAnswers) *huh.Group {
	desc := detectionText(project)
	if project.Primary == nil {
		confirm := huh.NewConfirm().
			Title("Continue with a manual profile?").
			Description("No automatic target will be recommended. A kit, if requested, will contain plan and security documents only.").
			Value(&answers.acceptDetection)
		return huh.NewGroup(
			huh.NewNote().Title("Project profile").Description(desc),
			confirm,
		).Title("Project profile")
	}
	return huh.NewGroup(
		huh.NewNote().Title("Detected profile").Description(desc),
		huh.NewConfirm().
			Title("Use this detected profile?").
			Description("If not, Deskweaver stops at manual review instead of guessing.").
			Value(&answers.acceptDetection).
			Affirmative("Yes, use it").
			Negative("No, manual review"),
	).Title("Project profile")
}

func detectionText(project *model.Project) string {
	var b strings.Builder
	if project.Primary != nil {
		p := project.Primary
		fmt.Fprintf(&b, "%s", p.Name)
		if p.Version != "" {
			fmt.Fprintf(&b, " %s", p.Version)
		}
		fmt.Fprintf(&b, "\nTier %s · %s confidence · score %d/100", p.Tier, p.Confidence, p.Score)
		if len(p.Capabilities) > 0 {
			fmt.Fprintf(&b, "\nCapabilities: %s", strings.Join(p.Capabilities, ", "))
		}
	} else {
		b.WriteString("No known framework matched. Continue with a manual profile or rescan another directory.")
	}
	fmt.Fprintf(&b, "\nFiles: %d scanned, %d skipped", project.ScannedFiles, project.SkippedFiles)
	if project.Monorepo {
		b.WriteString("\nMonorepo detected.")
	}
	if len(project.Warnings) > 0 {
		b.WriteString("\n\nWarnings:\n")
		for _, w := range project.Warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
	}
	if len(project.Unknowns) > 0 {
		b.WriteString("\nUnknowns:\n")
		for _, u := range project.Unknowns {
			fmt.Fprintf(&b, "- %s\n", u)
		}
	}
	return strings.TrimSpace(b.String())
}

func printSummary(out io.Writer, project *model.Project) {
	if project.Primary != nil {
		fmt.Fprintf(out, "Detected %s (%s confidence, Tier %s).\n", project.Primary.Name, project.Primary.Confidence, project.Primary.Tier)
	} else {
		fmt.Fprintln(out, "No known framework matched.")
	}
	for _, w := range project.Warnings {
		fmt.Fprintf(out, "warning: %s\n", w)
	}
	fmt.Fprintln(out)
}

func newForm(opts Options, groups ...*huh.Group) *huh.Form {
	theme := huh.ThemeCharm()
	if opts.NoColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		theme = huh.ThemeBase()
	}
	form := huh.NewForm(groups...).
		WithTheme(theme).
		WithShowHelp(true).
		WithWidth(92)
	if opts.In != nil {
		form = form.WithInput(opts.In)
	}
	if opts.Out != nil {
		form = form.WithOutput(opts.Out)
	}
	if os.Getenv("TERM") == "dumb" {
		form = form.WithAccessible(true)
	}
	return form
}

func mapCancel(err error) error {
	if errors.Is(err, huh.ErrUserAborted) || errors.Is(err, context.Canceled) {
		return ErrCancelled
	}
	return err
}

func defaultTargets() []string {
	targets := []string{"linux", "windows"}
	return targets
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

func formatOptions(targets []string) []huh.Option[string] {
	seen := map[string]bool{}
	var out []huh.Option[string]
	add := func(label, value string) {
		if seen[value] {
			return
		}
		seen[value] = true
		out = append(out, huh.NewOption(label, value))
	}
	for _, t := range targets {
		switch t {
		case "linux":
			add("Flatpak (sandboxed)", "flatpak")
			add("AppImage", "appimage")
			add("deb package", "deb")
			add("rpm package", "rpm")
			add("Tarball", "tarball")
		case "windows":
			add("NSIS installer", "nsis")
			add("MSI installer", "msi")
			add("Portable ZIP", "portable")
			add("MSIX package", "msix")
		case "macos":
			add("DMG", "dmg")
			add("App bundle", "app")
			add("PKG installer", "pkg")
		case "android":
			add("APK", "apk")
			add("Android App Bundle (AAB)", "aab")
		case "ios":
			add("IPA (store build)", "ipa")
		}
	}
	return out
}

func sanitizeFormats(formats, targets []string) []string {
	allowed := map[string]bool{}
	for _, o := range formatOptions(targets) {
		allowed[o.Value] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range formats {
		if allowed[f] && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

func candidateOptions(project *model.Project) []huh.Option[string] {
	options := []huh.Option[string]{huh.NewOption("Use Deskweaver's recommendation", "")}
	primary := ""
	if project.Primary != nil {
		primary = project.Primary.DefaultTarget
	}
	for _, c := range recommend.All() {
		label := c.Name
		if c.ID == primary {
			label += " (framework default)"
		}
		options = append(options, huh.NewOption(label, c.ID))
	}
	return options
}

func hasDesktop(targets []string) bool {
	for _, t := range targets {
		switch t {
		case "linux", "windows", "macos":
			return true
		}
	}
	return false
}

func defaultStartPath() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	if looksLikeProject(cwd) {
		return cwd
	}
	return ""
}

func defaultPlaceholder() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "~/repos/my-app"
	}
	return cwd
}

func looksLikeProject(dir string) bool {
	for _, name := range []string{
		"package.json", "requirements.txt", "pyproject.toml", "composer.json",
		"go.mod", "Cargo.toml", "index.html", "Gemfile", "pom.xml",
		"build.gradle", "build.gradle.kts", "artisan", "manage.py",
	} {
		if st, err := os.Stat(filepath.Join(dir, name)); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

func validateDir(s string) error {
	path, err := expandPath(s)
	if err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("directory does not exist")
		}
		return errors.New("cannot access directory")
	}
	if !st.IsDir() {
		return errors.New("path is not a directory")
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("directory is not readable")
	}
	_, _ = f.Readdirnames(1)
	return f.Close()
}

func expandPath(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("path is required")
	}
	if (strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"")) || (strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'")) {
		s = s[1 : len(s)-1]
	}
	s = os.ExpandEnv(s)
	if s == "~" || strings.HasPrefix(s, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if s == "~" {
			s = home
		} else {
			s = filepath.Join(home, s[2:])
		}
	}
	abs, err := filepath.Abs(s)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func dirSuggestions(input string) []string {
	if strings.TrimSpace(input) == "" {
		return nil
	}
	p := os.ExpandEnv(input)
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			if p == "~" {
				p = home
			} else {
				p = filepath.Join(home, p[2:])
			}
		}
	}
	dir := p
	if !strings.HasSuffix(p, string(filepath.Separator)) {
		dir = filepath.Dir(p)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name())+string(filepath.Separator))
		if len(out) >= 8 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func progressPrinter(out io.Writer) func(app.Progress) {
	return func(p app.Progress) {
		if p.Detail == "" {
			return
		}
		fmt.Fprintf(out, "  [%3d%%] %s\n", p.Percent, p.Detail)
	}
}
