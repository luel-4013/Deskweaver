package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := RunContext(context.Background(), args, strings.NewReader(""), &out, &errOut)
	return code, out.String(), errOut.String()
}

func writeFixture(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		"package.json":   `{"name":"demo-app","version":"1.0.0","dependencies":{"react":"^19.0.0","react-dom":"^19.0.0"},"devDependencies":{"vite":"^8.0.0"}}`,
		"vite.config.ts": `export default {}`,
		"index.html":     `<div id="root"></div>`,
		"src/main.tsx":   `console.log("demo")`,
	}
	for name, body := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func decode[T any](t *testing.T, s string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, s)
	}
	return v
}

func TestNoArgsFailsClosedWithoutTTY(t *testing.T) {
	code, out, errOut := runCLI(t)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	if out != "" {
		t.Fatalf("stdout should be empty, got %q", out)
	}
	if !strings.Contains(errOut, "interactive terminal") {
		t.Fatalf("stderr = %q, want a clear non-interactive message", errOut)
	}
}

func TestScanJSON(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root)
	code, out, errOut := runCLI(t, "scan", root, "--json", "--no-exec")
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	var project struct {
		Schema  string `json:"schema"`
		Name    string `json:"name"`
		Primary *struct {
			RuleID string `json:"rule_id"`
		} `json:"primary"`
	}
	project = decode[struct {
		Schema  string `json:"schema"`
		Name    string `json:"name"`
		Primary *struct {
			RuleID string `json:"rule_id"`
		} `json:"primary"`
	}](t, out)
	if project.Schema != "deskweaver.project/v1" || project.Name != "demo-app" {
		t.Fatalf("unexpected project JSON: %#v", project)
	}
	if project.Primary == nil || project.Primary.RuleID != "react" {
		t.Fatalf("primary = %#v, want react", project.Primary)
	}
}

func TestPlanJSONNoKitWritesNothing(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root)
	code, out, errOut := runCLI(t, "--json", "plan", "--no-input", "--no-kit", "--target", "linux", root)
	if code != exitOK && code != exitMissingDeps {
		t.Fatalf("exit = %d, want 0 or 3; stderr = %s", code, errOut)
	}
	var plan struct {
		Schema    string   `json:"schema"`
		PlanHash  string   `json:"plan_hash"`
		Artifacts []string `json:"artifacts"`
		Project   struct {
			Root string `json:"root"`
		} `json:"project"`
	}
	plan = decode[struct {
		Schema    string   `json:"schema"`
		PlanHash  string   `json:"plan_hash"`
		Artifacts []string `json:"artifacts"`
		Project   struct {
			Root string `json:"root"`
		} `json:"project"`
	}](t, out)
	if plan.Schema != "deskweaver.plan/v1" || plan.PlanHash == "" {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	if len(plan.Artifacts) != 0 {
		t.Fatalf("no-kit plan has artifacts: %v", plan.Artifacts)
	}
	if errOut != "" {
		t.Fatalf("JSON mode wrote progress to stderr: %q", errOut)
	}
}

func TestAnswersReplayResolvesPathsFromFile(t *testing.T) {
	base := t.TempDir()
	caseDir := filepath.Join(base, "case")
	project := filepath.Join(caseDir, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, project)
	answers := `# replay test
schema: deskweaver.answers/v1
project_path: project
targets: [linux]
formats: [flatpak]
profile: hardened
sensitivity: confidential
untrusted_input: true
network: offline
privilege: none
output_dir: kit
generate_kit: true
candidate: tauri
`
	answersPath := filepath.Join(caseDir, "answers.yaml")
	if err := os.WriteFile(answersPath, []byte(answers), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "plan", "--answers", answersPath, "--json")
	if code != exitOK && code != exitMissingDeps {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	var plan struct {
		Answers struct {
			ProjectPath string `json:"project_path"`
			OutputDir   string `json:"output_dir"`
			GenerateKit bool   `json:"generate_kit"`
		} `json:"answers"`
		Project struct {
			Root string `json:"root"`
		} `json:"project"`
	}
	plan = decode[struct {
		Answers struct {
			ProjectPath string `json:"project_path"`
			OutputDir   string `json:"output_dir"`
			GenerateKit bool   `json:"generate_kit"`
		} `json:"answers"`
		Project struct {
			Root string `json:"root"`
		} `json:"project"`
	}](t, out)
	if plan.Answers.ProjectPath != project {
		t.Fatalf("project_path = %q, want %q", plan.Answers.ProjectPath, project)
	}
	if plan.Project.Root != project {
		t.Fatalf("scanned root = %q, want %q", plan.Project.Root, project)
	}
	if plan.Answers.OutputDir != filepath.Join(caseDir, "kit") {
		t.Fatalf("output_dir = %q, want answers-file-relative kit", plan.Answers.OutputDir)
	}
	if !plan.Answers.GenerateKit {
		t.Fatal("generate_kit did not replay")
	}
	if _, err := os.Stat(filepath.Join(caseDir, "kit", "plan.json")); err != nil {
		t.Fatalf("kit was not generated at the resolved path: %v", err)
	}
}

func TestAnswersRejectsUnknownFields(t *testing.T) {
	base := t.TempDir()
	project := filepath.Join(base, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, project)
	answers := `schema: deskweaver.answers/v1
project_path: project
profiles: hardened
targets: [linux]
`
	path := filepath.Join(base, "answers.yaml")
	if err := os.WriteFile(path, []byte(answers), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "plan", "--answers", path, "--json")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d; stderr = %s", code, exitUsage, errOut)
	}
	if !strings.Contains(errOut, "profiles") {
		t.Fatalf("stderr = %q, want the unknown field to be named", errOut)
	}
}

func TestInvalidTargetExitCode(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root)
	code, _, errOut := runCLI(t, "plan", "--no-input", "--target", "solaris", root)
	if code != exitUnsupported {
		t.Fatalf("exit = %d, want %d; stderr = %s", code, exitUnsupported, errOut)
	}
	if !strings.Contains(errOut, "unsupported target") {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestNonEmptyOutputRefused(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root)
	out := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(out, "keep.txt")
	if err := os.WriteFile(marker, []byte("user data"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "plan", "--no-input", "--out", out, root)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d; stderr = %s", code, exitUsage, errOut)
	}
	b, err := os.ReadFile(marker)
	if err != nil || string(b) != "user data" {
		t.Fatalf("existing output was modified: %q, %v", b, err)
	}
}

func TestBundleRegeneratesAndVerifiesHash(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root)
	kitDir := filepath.Join(t.TempDir(), "kit")
	code, out, errOut := runCLI(t, "plan", "--no-input", "--json", "--out", kitDir, root)
	if code != exitOK && code != exitMissingDeps {
		t.Fatalf("plan exit = %d, stderr = %s", code, errOut)
	}
	var original struct {
		PlanHash string `json:"plan_hash"`
	}
	original = decode[struct {
		PlanHash string `json:"plan_hash"`
	}](t, out)
	if original.PlanHash == "" {
		t.Fatal("original plan has no hash")
	}

	bundleDir := filepath.Join(t.TempDir(), "bundle")
	code, out, errOut = runCLI(t, "bundle", filepath.Join(kitDir, "plan.json"), "--out", bundleDir, "--json")
	if code != exitOK {
		t.Fatalf("bundle exit = %d, stderr = %s", code, errOut)
	}
	var result struct {
		Schema   string   `json:"schema"`
		PlanHash string   `json:"plan_hash"`
		KitDir   string   `json:"kit_dir"`
		Files    []string `json:"files"`
	}
	result = decode[struct {
		Schema   string   `json:"schema"`
		PlanHash string   `json:"plan_hash"`
		KitDir   string   `json:"kit_dir"`
		Files    []string `json:"files"`
	}](t, out)
	if result.Schema != "deskweaver.bundle/v1" || result.KitDir != bundleDir {
		t.Fatalf("unexpected bundle result: %#v", result)
	}
	if result.PlanHash != original.PlanHash {
		t.Fatalf("bundle hash = %s, want %s", result.PlanHash, original.PlanHash)
	}
	for _, rel := range []string{"plan.json", "plan.md", "conversion/preflight.sh", "ARTIFACTS.sha256"} {
		if _, err := os.Stat(filepath.Join(bundleDir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("bundle missing %s: %v", rel, err)
		}
	}
	for _, file := range result.Files {
		if file == "ARTIFACTS.sha256" {
			continue
		}
		if _, err := os.Stat(filepath.Join(bundleDir, filepath.FromSlash(file))); err != nil {
			t.Fatalf("reported file %s is missing: %v", file, err)
		}
	}
}

func TestDoctorJSONCrossTarget(t *testing.T) {
	code, out, errOut := runCLI(t, "doctor", "--no-input", "--target", "linux", "--distro", "ubuntu-22.04", "--json")
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	var result struct {
		Schema string `json:"schema"`
		Host   struct {
			OS             string `json:"os"`
			Distro         string `json:"distro"`
			Family         string `json:"family"`
			PackageManager string `json:"package_manager"`
		} `json:"host"`
		ExitCode int `json:"exit_code"`
	}
	result = decode[struct {
		Schema string `json:"schema"`
		Host   struct {
			OS             string `json:"os"`
			Distro         string `json:"distro"`
			Family         string `json:"family"`
			PackageManager string `json:"package_manager"`
		} `json:"host"`
		ExitCode int `json:"exit_code"`
	}](t, out)
	if result.Schema != "deskweaver.doctor/v1" || result.Host.OS != "linux" {
		t.Fatalf("unexpected doctor result: %#v", result)
	}
	if result.Host.Distro != "ubuntu-22.04" || result.Host.Family != "debian" || result.Host.PackageManager != "apt-get" {
		t.Fatalf("distro override not applied: %#v", result.Host)
	}
	if result.ExitCode != exitOK {
		t.Fatalf("exit_code = %d", result.ExitCode)
	}
}

func TestTargetsJSON(t *testing.T) {
	code, out, errOut := runCLI(t, "targets", "--target", "linux,windows", "--json")
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	var result struct {
		Schema     string   `json:"schema"`
		Requested  []string `json:"requested"`
		Candidates []struct {
			ID string `json:"id"`
			OS []struct {
				OS    string `json:"os"`
				Level int    `json:"level"`
			} `json:"os"`
		} `json:"candidates"`
	}
	result = decode[struct {
		Schema     string   `json:"schema"`
		Requested  []string `json:"requested"`
		Candidates []struct {
			ID string `json:"id"`
			OS []struct {
				OS    string `json:"os"`
				Level int    `json:"level"`
			} `json:"os"`
		} `json:"candidates"`
	}](t, out)
	if result.Schema != "deskweaver.targets/v1" || len(result.Candidates) != len(recommendIDs(t)) {
		t.Fatalf("unexpected targets result: schema=%s candidates=%d", result.Schema, len(result.Candidates))
	}
	for _, c := range result.Candidates {
		if len(c.OS) != 5 {
			t.Fatalf("%s has %d OS entries, want 5", c.ID, len(c.OS))
		}
	}
}

func recommendIDs(t *testing.T) []string {
	t.Helper()
	return []string{
		"tauri", "electron", "pwa", "capacitor", "cordova", "wails", "pywebview",
		"neutralino", "nativephp", "maui", "flutter", "qt", "container", "modernize",
		"privileged-service", "rewrite",
	}
}

func TestRulesAndSelfCheck(t *testing.T) {
	code, out, errOut := runCLI(t, "rules", "verify", "--json")
	if code != exitOK {
		t.Fatalf("rules verify exit = %d, stderr = %s", code, errOut)
	}
	var verify struct {
		Schema    string `json:"schema"`
		Rules     int    `json:"rules"`
		Signed    bool   `json:"signed"`
		Integrity string `json:"integrity"`
	}
	verify = decode[struct {
		Schema    string `json:"schema"`
		Rules     int    `json:"rules"`
		Signed    bool   `json:"signed"`
		Integrity string `json:"integrity"`
	}](t, out)
	if verify.Schema != "deskweaver.rules.verify/v1" || verify.Rules != 65 || verify.Signed {
		t.Fatalf("unexpected verify result: %#v", verify)
	}
	if verify.Integrity != "sha256-of-catalog-json" {
		t.Fatalf("integrity = %q", verify.Integrity)
	}

	code, out, errOut = runCLI(t, "self-check", "--json")
	if code != exitOK {
		t.Fatalf("self-check exit = %d, stderr = %s", code, errOut)
	}
	var self struct {
		Schema string `json:"schema"`
		Failed int    `json:"failed"`
	}
	self = decode[struct {
		Schema string `json:"schema"`
		Failed int    `json:"failed"`
	}](t, out)
	if self.Schema != "deskweaver.self_check/v1" || self.Failed != 0 {
		t.Fatalf("unexpected self-check result: %#v", self)
	}
}

func TestVersionJSON(t *testing.T) {
	code, out, errOut := runCLI(t, "version", "--json")
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	var result struct {
		Schema  string `json:"schema"`
		Version string `json:"version"`
	}
	result = decode[struct {
		Schema  string `json:"schema"`
		Version string `json:"version"`
	}](t, out)
	if result.Schema != "deskweaver.version/v1" || result.Version == "" {
		t.Fatalf("unexpected version result: %#v", result)
	}
}

func TestExplainUnknownID(t *testing.T) {
	code, _, errOut := runCLI(t, "explain", "definitely-not-a-rule", "--json")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut, "unknown rule or candidate") {
		t.Fatalf("stderr = %q", errOut)
	}
}
