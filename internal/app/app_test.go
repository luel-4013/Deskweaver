package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luel-4013/deskweaver/internal/model"
)

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"package.json":   `{"name":"demo-app","dependencies":{"react":"^19.0.0","react-dom":"^19.0.0"},"devDependencies":{"vite":"^8.0.0"}}`,
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
	return root
}

func baseOptions(t *testing.T, root, out string) Options {
	t.Helper()
	return Options{
		ProjectPath: root, Targets: []string{"linux"}, Profile: "hardened",
		Sensitivity: "confidential", Network: "offline", Privilege: "none",
		OutputDir: out, GenerateKit: true, NoInput: true,
		ProbeTimeout: 2 * time.Second,
		Now:          func() time.Time { return time.Unix(1700000000, 0) },
	}
}

func TestRunGeneratesPlanAndKit(t *testing.T) {
	root := fixture(t)
	out := filepath.Join(t.TempDir(), "out")
	res, err := Run(context.Background(), baseOptions(t, root, out))
	if err != nil {
		t.Fatal(err)
	}
	plan := res.Plan
	if plan.Project.Primary == nil || plan.Project.Primary.RuleID != "react" {
		t.Fatalf("primary = %#v", plan.Project.Primary)
	}
	if plan.Recommendation.Primary == nil || plan.Recommendation.Primary.ID != "tauri" {
		t.Fatalf("recommendation = %#v", plan.Recommendation.Primary)
	}
	if plan.PlanHash == "" {
		t.Fatal("empty plan hash")
	}
	if res.KitDir != out {
		t.Fatalf("kit dir = %q, want %q", res.KitDir, out)
	}
	for _, rel := range []string{"plan.md", "plan.json", "answers.yaml", "security/SECURITY.md", "conversion/preflight.sh"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(rel))); err != nil {
			t.Errorf("missing %s: %v", rel, err)
		}
	}
	// plan.json must round-trip to the same decision hash.
	b, err := os.ReadFile(filepath.Join(out, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.Plan
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := PlanHash(decoded); got != decoded.PlanHash {
		t.Fatalf("plan.json hash mismatch: recomputed %s, stored %s", got, decoded.PlanHash)
	}
}

func TestPlanHashIsDeterministic(t *testing.T) {
	root := fixture(t)
	out := filepath.Join(t.TempDir(), "out")
	first, err := Run(context.Background(), baseOptions(t, root, out))
	if err != nil {
		t.Fatal(err)
	}
	opts := baseOptions(t, root, out)
	opts.Force = true
	second, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.Plan.PlanHash != second.Plan.PlanHash {
		t.Fatalf("hash changed: %s vs %s", first.Plan.PlanHash, second.Plan.PlanHash)
	}
}

func TestNoKitWritesNothing(t *testing.T) {
	root := fixture(t)
	out := filepath.Join(t.TempDir(), "never-created")
	opts := baseOptions(t, root, out)
	opts.GenerateKit = false
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.KitFiles) != 0 || res.KitDir != "" {
		t.Fatalf("kit should be empty: %#v", res)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("output directory was created despite no-kit")
	}
}

func TestRedactRemovesHomeAndRoot(t *testing.T) {
	root := fixture(t)
	opts := baseOptions(t, root, filepath.Join(t.TempDir(), "out"))
	opts.GenerateKit = false
	opts.Redact = true
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Plan.Project.Root != "." || res.Plan.Answers.ProjectPath != "." {
		t.Fatalf("root not redacted: %q %q", res.Plan.Project.Root, res.Plan.Answers.ProjectPath)
	}
	b, _ := json.Marshal(res.Plan)
	home, _ := os.UserHomeDir()
	if home != "" && strings.Contains(string(b), home) {
		t.Fatal("plan still contains the home directory")
	}
}

func TestMonorepoWithoutWorkspaceBlocks(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"root","workspaces":["packages/*"]}`)
	write("packages/web/package.json", `{"name":"web","dependencies":{"next":"15.0.0","react":"19.0.0"}}`)
	write("packages/web/next.config.js", `module.exports = {}`)
	opts := baseOptions(t, root, filepath.Join(t.TempDir(), "out"))
	opts.GenerateKit = false
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range res.Plan.Recommendation.Blockers {
		if strings.Contains(b, "workspace") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected workspace blocker, got %v", res.Plan.Recommendation.Blockers)
	}
}
