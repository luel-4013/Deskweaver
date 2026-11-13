// Package kit renders the review-only conversion package.
//
// Generate writes only inside a newly staged directory and commits it with a
// rename. It never executes a generated script, never writes into the scanned
// project, and never invokes a package manager or elevation tool.
package kit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luel-4013/deskweaver/internal/model"
	"gopkg.in/yaml.v3"
)

// ManifestName is the checksum manifest written last.
const ManifestName = "ARTIFACTS.sha256"

// Options controls output placement.
type Options struct {
	OutputDir string
	Force     bool
}

// Result describes a committed kit.
type Result struct {
	Dir       string
	Files     []string
	BackupDir string
}

// CanConvert reports whether the recommendation has a real conversion path.
func CanConvert(rec model.Recommendation) bool {
	if rec.Primary == nil || len(rec.Blockers) > 0 || rec.ManualReview {
		return false
	}
	switch rec.Primary.ID {
	case "modernize", "container", "rewrite":
		return false
	default:
		return true
	}
}

// PlannedFiles returns every relative file the generator will write. It is
// deterministic and is also recorded in plan.json.
func PlannedFiles(plan model.Plan) []string {
	files := []string{
		"README.md",
		"plan.md",
		"plan.json",
		"answers.yaml",
		"security/SECURITY.md",
		"security/controls.yaml",
		"security/csp.txt",
		"docs/REVIEW-CHECKLIST.md",
		"docs/ROLLBACK.md",
		"docs/EXPECTED-OUTPUT.md",
		"sbom/README.md",
	}
	if hasServer(plan) {
		files = append(files,
			"security/local-api-middleware.py",
			"security/local-api-middleware.ts",
		)
	}
	if CanConvert(plan.Recommendation) {
		files = append(files,
			"conversion/README.md",
			"conversion/preflight.sh",
			"conversion/commands.txt",
			"conversion/scaffold-plan.md",
			"conversion/build-plan.md",
			"packaging/linux/README.md",
			"packaging/windows/README.md",
			"ci/build.yml",
		)
		switch plan.Recommendation.Primary.ID {
		case "tauri":
			files = append(files, "security/tauri.conf.json", "security/capabilities/default.json")
		case "electron":
			files = append(files, "security/electron-main.cjs", "security/preload.cjs")
		case "wails":
			files = append(files, "security/wails-notes.md")
		case "pywebview":
			files = append(files, "security/pywebview-host.py")
		case "nativephp":
			files = append(files, "security/nativephp-notes.md")
		case "capacitor", "cordova":
			files = append(files, "security/mobile-webview-notes.md")
		case "pwa":
			files = append(files, "security/pwa-notes.md")
		case "neutralino":
			files = append(files, "security/neutralino-notes.md")
		case "maui":
			files = append(files, "security/maui-notes.md")
		case "privileged-service":
			files = append(files, "security/privileged-service.md")
		case "flutter", "qt":
			files = append(files, "security/native-rewrite-notes.md")
		}
	}
	files = append(files, ManifestName)
	sort.Strings(files)
	return files
}

// Generate renders and atomically commits the kit.
func Generate(ctx context.Context, plan model.Plan, opts Options) (Result, error) {
	out, err := prepareOutput(opts.OutputDir, opts.Force)
	if err != nil {
		return Result{}, err
	}
	parent := filepath.Dir(out)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Result{}, fmt.Errorf("create output parent: %w", err)
	}
	stage, err := os.MkdirTemp(parent, ".deskweaver-stage-")
	if err != nil {
		return Result{}, fmt.Errorf("create staging directory: %w", err)
	}
	defer os.RemoveAll(stage)

	expected := PlannedFiles(plan)
	if len(plan.Artifacts) > 0 && !equalStrings(expected, plan.Artifacts) {
		return Result{}, fmt.Errorf("internal error: plan artifact list does not match generator")
	}

	contents, err := renderAll(plan)
	if err != nil {
		return Result{}, err
	}
	for _, rel := range expected {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if rel == ManifestName {
			continue
		}
		data, ok := contents[rel]
		if !ok {
			return Result{}, fmt.Errorf("internal error: no content for %s", rel)
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(rel, ".sh") || strings.HasSuffix(rel, ".py") {
			mode = 0o755
		}
		if err := safeWrite(stage, rel, data, mode); err != nil {
			return Result{}, err
		}
	}

	manifest, err := buildManifest(stage, expected)
	if err != nil {
		return Result{}, err
	}
	if err := safeWrite(stage, ManifestName, manifest, 0o644); err != nil {
		return Result{}, err
	}

	backup, err := commit(out, opts.Force)
	if err == nil {
		err = os.Rename(stage, out)
	}
	if err != nil {
		if backup != "" {
			_ = os.Rename(backup, out)
		}
		return Result{}, err
	}
	return Result{Dir: out, Files: expected, BackupDir: backup}, nil
}

func prepareOutput(out string, force bool) (string, error) {
	if strings.TrimSpace(out) == "" {
		return "", fmt.Errorf("output directory is required")
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}
	abs = filepath.Clean(abs)
	if abs == string(filepath.Separator) {
		return "", fmt.Errorf("refusing to use the filesystem root as output")
	}
	if home, err := os.UserHomeDir(); err == nil && abs == filepath.Clean(home) {
		return "", fmt.Errorf("refusing to use the home directory as output")
	}
	if st, err := os.Lstat(abs); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing to write through a symlinked output path: %s", abs)
		}
		if !st.IsDir() {
			return "", fmt.Errorf("output path exists and is not a directory: %s", abs)
		}
		entries, err := os.ReadDir(abs)
		if err != nil {
			return "", fmt.Errorf("read output directory: %w", err)
		}
		if len(entries) > 0 && !force {
			return "", fmt.Errorf("output directory exists and is not empty (pass --force to replace it with a timestamped backup): %s", abs)
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect output path: %w", err)
	}
	return abs, nil
}

func commit(out string, force bool) (string, error) {
	st, err := os.Lstat(out)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("output path is not a directory: %s", out)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		if err := os.Remove(out); err != nil {
			return "", fmt.Errorf("remove empty output directory: %w", err)
		}
		return "", nil
	}
	if !force {
		return "", fmt.Errorf("output directory exists and is not empty: %s", out)
	}
	backup := out + ".backup-" + time.Now().UTC().Format("20060102T150405Z")
	for i := 2; ; i++ {
		if _, err := os.Lstat(backup); os.IsNotExist(err) {
			break
		}
		backup = fmt.Sprintf("%s.%d", backup, i)
	}
	if err := os.Rename(out, backup); err != nil {
		return "", fmt.Errorf("move existing output to backup: %w", err)
	}
	return backup, nil
}

func safeWrite(root, rel string, data []byte, mode os.FileMode) error {
	rel = filepath.FromSlash(rel)
	clean := filepath.Clean(rel)
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return fmt.Errorf("unsafe generated path %q", rel)
	}
	full := filepath.Join(root, clean)
	check, err := filepath.Rel(root, full)
	if err != nil || strings.HasPrefix(check, "..") {
		return fmt.Errorf("generated path escapes output directory: %q", rel)
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return fmt.Errorf("create directory for %s: %w", rel, err)
	}
	// #nosec G304 -- path is validated above and rooted in the staging dir.
	f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", rel, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", rel, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s: %w", rel, err)
	}
	return f.Close()
}

func buildManifest(root string, files []string) ([]byte, error) {
	var lines []string
	for _, rel := range files {
		if rel == ManifestName {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(rel))
		// #nosec G304 -- fixed manifest paths under the staging root.
		b, err := os.ReadFile(full)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		lines = append(lines, hex.EncodeToString(sum[:])+"  "+rel)
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func hasServer(plan model.Plan) bool {
	if plan.Project.Primary != nil {
		for _, c := range plan.Project.Primary.Capabilities {
			if strings.EqualFold(c, "server") {
				return true
			}
		}
	}
	for _, c := range plan.Project.Capabilities {
		if strings.EqualFold(c, "server") {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func renderAll(plan model.Plan) (map[string][]byte, error) {
	out := make(map[string][]byte)
	add := func(path string, b []byte) { out[path] = b }
	addText := func(path, s string) { out[path] = []byte(s) }

	planJSON, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, err
	}
	add("plan.json", append(planJSON, '\n'))

	answersDoc := struct {
		Schema        string `yaml:"schema"`
		model.Answers `yaml:",inline"`
	}{Schema: "deskweaver.answers/v1", Answers: plan.Answers}
	answersYAML, err := yaml.Marshal(answersDoc)
	if err != nil {
		return nil, err
	}
	add("answers.yaml", append([]byte("# Generated by Deskweaver. This file records reviewed answers; it is not executed.\n"), answersYAML...))

	controlsDoc := struct {
		Schema        string            `yaml:"schema"`
		PlanHash      string            `yaml:"plan_hash"`
		Profile       string            `yaml:"profile"`
		ThreatModel   model.ThreatModel `yaml:"threat_model"`
		Controls      []model.Control   `yaml:"controls"`
		ResidualRisks []string          `yaml:"residual_risks"`
		Checklist     []string          `yaml:"checklist"`
	}{
		Schema: "deskweaver.controls/v1", PlanHash: plan.PlanHash, Profile: plan.Security.Profile,
		ThreatModel: plan.Security.ThreatModel, Controls: plan.Security.Controls,
		ResidualRisks: plan.Security.ResidualRisks, Checklist: plan.Security.Checklist,
	}
	controlsYAML, err := yaml.Marshal(controlsDoc)
	if err != nil {
		return nil, err
	}
	add("security/controls.yaml", append([]byte("# Generated by Deskweaver. Review-only checklist.\n"), controlsYAML...))

	addText("README.md", renderReadme(plan))
	addText("plan.md", renderPlan(plan))
	addText("security/SECURITY.md", renderSecurity(plan))
	addText("security/csp.txt", renderCSP(plan))
	addText("docs/REVIEW-CHECKLIST.md", renderReviewChecklist(plan))
	addText("docs/ROLLBACK.md", renderRollback(plan))
	addText("docs/EXPECTED-OUTPUT.md", renderExpectedOutput(plan))
	addText("sbom/README.md", renderSBOM(plan))

	if hasServer(plan) {
		addText("security/local-api-middleware.py", pyMiddleware)
		addText("security/local-api-middleware.ts", tsMiddleware)
	}

	if CanConvert(plan.Recommendation) {
		addText("conversion/README.md", renderConversionReadme(plan))
		addText("conversion/preflight.sh", renderPreflight(plan))
		addText("conversion/commands.txt", renderCommands(plan))
		addText("conversion/scaffold-plan.md", renderScaffoldPlan(plan))
		addText("conversion/build-plan.md", renderBuildPlan(plan))
		addText("packaging/linux/README.md", renderLinuxPackaging(plan))
		addText("packaging/windows/README.md", renderWindowsPackaging(plan))
		addText("ci/build.yml", renderCI(plan))
		switch plan.Recommendation.Primary.ID {
		case "tauri":
			addText("security/tauri.conf.json", tauriConfig)
			addText("security/capabilities/default.json", tauriCapability)
		case "electron":
			addText("security/electron-main.cjs", electronMain)
			addText("security/preload.cjs", electronPreload)
		case "wails":
			addText("security/wails-notes.md", wailsNotes)
		case "pywebview":
			addText("security/pywebview-host.py", pywebviewHost)
		case "nativephp":
			addText("security/nativephp-notes.md", nativephpNotes)
		case "capacitor", "cordova":
			addText("security/mobile-webview-notes.md", mobileNotes)
		case "pwa":
			addText("security/pwa-notes.md", pwaNotes)
		case "neutralino":
			addText("security/neutralino-notes.md", neutralinoNotes)
		case "maui":
			addText("security/maui-notes.md", mauiNotes)
		case "privileged-service":
			addText("security/privileged-service.md", privilegedNotes)
		case "flutter", "qt":
			addText("security/native-rewrite-notes.md", nativeRewriteNotes)
		}
	}
	return out, nil
}
