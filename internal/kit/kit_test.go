package kit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luel-4013/deskweaver/internal/model"
)

func samplePlan() model.Plan {
	return model.Plan{
		Schema:           "deskweaver.plan/v1",
		ToolVersion:      "0.1.0-test",
		RulesVersion:     "0.1.0",
		RulesHash:        "abc",
		GeneratedAt:      time.Unix(0, 0).UTC().Format(time.RFC3339),
		PlanHash:         "deadbeef",
		ArtifactManifest: ManifestName,
		Project: model.Project{
			Schema: "deskweaver.project/v1", Name: "demo", Root: "/tmp/demo",
			ScannedFiles: 3, Capabilities: []string{"static"},
			Primary: &model.Detection{RuleID: "react", Name: "React", Tier: model.TierA, Language: "node", Capabilities: []string{"static"}},
		},
		Answers: model.Answers{
			ProjectPath: "/tmp/demo", Targets: []string{"linux", "windows"},
			Profile: "hardened", Sensitivity: "internal", Network: "offline",
			Privilege: "none", GenerateKit: true,
		},
		Host: model.Host{OS: "linux", Arch: "amd64"},
		Recommendation: model.Recommendation{
			Primary:          &model.RankedCandidate{ID: "tauri", Name: "Tauri 2", Score: 80},
			RequestedTargets: []string{"linux", "windows"},
			OSMatrix: []model.OSSupport{
				{OS: "linux", Level: 3, Label: model.OSLabel(3)},
				{OS: "windows", Level: 3, Label: model.OSLabel(3)},
			},
			Architecture: "Rust + WebView",
		},
		Security: model.SecurityPlan{
			Profile:       "hardened",
			ThreatModel:   model.ThreatModel{Sensitivity: "internal", Network: "offline", Privilege: "none"},
			Controls:      []model.Control{{ID: "SEC-CSP-01", Name: "CSP", Status: "required", Detail: "strict"}},
			ResidualRisks: []string{"upstream zero-days"},
			Checklist:     []string{"review"},
		},
	}
}

func TestGenerateCreatesReviewOnlyKit(t *testing.T) {
	plan := samplePlan()
	plan.Artifacts = PlannedFiles(plan)
	out := filepath.Join(t.TempDir(), "out")
	res, err := Generate(context.Background(), plan, Options{OutputDir: out})
	if err != nil {
		t.Fatal(err)
	}
	if res.Dir != out {
		t.Fatalf("dir = %q, want %q", res.Dir, out)
	}
	for _, rel := range []string{"plan.md", "plan.json", "answers.yaml", "security/SECURITY.md", "security/controls.yaml", "conversion/preflight.sh", "security/tauri.conf.json", "ARTIFACTS.sha256"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(rel))); err != nil {
			t.Errorf("missing %s: %v", rel, err)
		}
	}
	st, err := os.Stat(filepath.Join(out, "conversion", "preflight.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o100 == 0 {
		t.Fatal("preflight.sh is not executable")
	}
}

func TestGeneratedFilesContainNoDangerousPatterns(t *testing.T) {
	plan := samplePlan()
	plan.Artifacts = PlannedFiles(plan)
	out := filepath.Join(t.TempDir(), "out")
	if _, err := Generate(context.Background(), plan, Options{OutputDir: out}); err != nil {
		t.Fatal(err)
	}
	bad := []string{"sudo ", "sudo\t", "curl | sh", "curl|sh", "wget -O- | sh", "rm -rf", "mkfs.", "dd if=", "chmod 777", ":(){", "git clean -fdx"}
	err := filepath.WalkDir(out, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lower := strings.ToLower(string(b))
		for _, pattern := range bad {
			if strings.Contains(lower, pattern) {
				t.Errorf("%s contains dangerous pattern %q", path, pattern)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNonEmptyOutputRefusedWithoutForce(t *testing.T) {
	out := t.TempDir()
	marker := filepath.Join(out, "keep.txt")
	if err := os.WriteFile(marker, []byte("user data"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := samplePlan()
	plan.Artifacts = PlannedFiles(plan)
	if _, err := Generate(context.Background(), plan, Options{OutputDir: out}); err == nil {
		t.Fatal("expected refusal for non-empty output")
	}
	b, err := os.ReadFile(marker)
	if err != nil || string(b) != "user data" {
		t.Fatalf("existing file was modified: %q, %v", b, err)
	}
}

func TestForceCreatesBackup(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "keep.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := samplePlan()
	plan.Artifacts = PlannedFiles(plan)
	res, err := Generate(context.Background(), plan, Options{OutputDir: out, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.BackupDir == "" {
		t.Fatal("expected a backup directory")
	}
	if b, err := os.ReadFile(filepath.Join(res.BackupDir, "keep.txt")); err != nil || string(b) != "old" {
		t.Fatalf("backup did not preserve old file: %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(out, "plan.md")); err != nil {
		t.Fatal("new kit missing after force")
	}
}

func TestBlockedPlanHasNoConversionDirectory(t *testing.T) {
	plan := samplePlan()
	plan.Recommendation.Primary = &model.RankedCandidate{ID: "modernize", Name: "Modernize first"}
	plan.Recommendation.Blockers = []string{"modernize first"}
	plan.Artifacts = PlannedFiles(plan)
	out := filepath.Join(t.TempDir(), "out")
	if _, err := Generate(context.Background(), plan, Options{OutputDir: out}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "conversion")); !os.IsNotExist(err) {
		t.Fatal("blocked plan must not generate conversion scripts")
	}
	if _, err := os.Stat(filepath.Join(out, "plan.md")); err != nil {
		t.Fatal("blocked plan should still generate plan.md")
	}
}

func TestCanConvert(t *testing.T) {
	rec := model.Recommendation{Primary: &model.RankedCandidate{ID: "tauri"}}
	if !CanConvert(rec) {
		t.Fatal("tauri should be convertible")
	}
	if CanConvert(model.Recommendation{Primary: &model.RankedCandidate{ID: "container"}}) {
		t.Fatal("container is not a desktop conversion")
	}
	rec.Blockers = []string{"x"}
	if CanConvert(rec) {
		t.Fatal("blockers must disable conversion")
	}
}
