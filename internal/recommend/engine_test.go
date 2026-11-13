package recommend

import (
	"testing"

	"github.com/luel-4013/deskweaver/internal/model"
)

func project(id string, caps ...string) *model.Project {
	return &model.Project{
		Name: "demo",
		Primary: &model.Detection{
			RuleID: id, Name: id, Tier: model.TierA,
			Language: "node", Confidence: model.ConfidenceHigh, Score: 90,
			Capabilities: caps,
		},
		Capabilities: caps,
	}
}

func answers(targets ...string) model.Answers {
	return model.Answers{
		Targets: targets, Profile: "hardened", Sensitivity: "internal",
		Network: "offline", Privilege: "none", GenerateKit: true,
	}
}

func TestStaticPrefersTauri(t *testing.T) {
	rec := Recommend(project("react", "static"), answers("linux", "windows"), Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "tauri" {
		t.Fatalf("primary = %#v, want tauri", rec.Primary)
	}
	if rec.Fallback == nil {
		t.Fatal("expected a fallback")
	}
	if len(rec.OSMatrix) == 0 {
		t.Fatal("expected an OS matrix")
	}
}

func TestNextServerPrefersElectron(t *testing.T) {
	rec := Recommend(project("nextjs", "server", "node"), answers("linux", "windows"), Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "electron" {
		t.Fatalf("primary = %#v, want electron", rec.Primary)
	}
}

func TestPythonPrefersElectronSidecar(t *testing.T) {
	rec := Recommend(project("django", "server", "python", "database"), answers("linux", "windows"), Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "electron" {
		t.Fatalf("primary = %#v, want electron", rec.Primary)
	}
}

func TestLaravelPrefersNativePHP(t *testing.T) {
	rec := Recommend(project("laravel", "server", "php", "database", "laravel"), answers("linux", "windows"), Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "nativephp" {
		t.Fatalf("primary = %#v, want nativephp", rec.Primary)
	}
}

func TestGoPrefersWails(t *testing.T) {
	rec := Recommend(project("go-http", "server", "go"), answers("linux", "windows"), Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "wails" {
		t.Fatalf("primary = %#v, want wails", rec.Primary)
	}
}

func TestRustPrefersTauri(t *testing.T) {
	rec := Recommend(project("axum", "server", "rust"), answers("linux", "windows"), Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "tauri" {
		t.Fatalf("primary = %#v, want tauri", rec.Primary)
	}
}

func TestLegacyRequiresModernization(t *testing.T) {
	rec := Recommend(project("jsp-servlet", "legacy", "server", "java"), answers("linux", "windows"), Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "modernize" {
		t.Fatalf("primary = %#v, want modernize", rec.Primary)
	}
	if len(rec.Blockers) == 0 {
		t.Fatal("legacy recommendation must have a blocker")
	}
}

func TestJupyterIsNotDesktopApp(t *testing.T) {
	rec := Recommend(project("jupyter", "do-not-package", "python"), answers("linux", "windows"), Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "container" {
		t.Fatalf("primary = %#v, want container", rec.Primary)
	}
	if len(rec.Blockers) == 0 {
		t.Fatal("do-not-package recommendation must have a blocker")
	}
}

func TestCMSPrefersContainer(t *testing.T) {
	rec := Recommend(project("wordpress", "cms", "server", "php", "database"), answers("linux", "windows"), Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "container" {
		t.Fatalf("primary = %#v, want container for a CMS", rec.Primary)
	}
	if len(rec.Blockers) == 0 {
		t.Fatal("container recommendation must have a blocker")
	}
}

func TestHostileInputPrefersElectron(t *testing.T) {
	a := answers("linux", "windows")
	a.UntrustedInput = true
	rec := Recommend(project("react", "static"), a, Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "electron" {
		t.Fatalf("primary = %#v, want electron", rec.Primary)
	}
}

func TestPrivilegedPrefersSplitService(t *testing.T) {
	a := answers("linux", "windows")
	a.Privilege = "privileged-service"
	rec := Recommend(project("react", "static"), a, Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "privileged-service" {
		t.Fatalf("primary = %#v, want privileged-service", rec.Primary)
	}
}

func TestTierCBlocksRecommendation(t *testing.T) {
	p := project("react-native", "mobile-first", "native")
	p.Primary.Tier = model.TierC
	rec := Recommend(p, answers("linux"), Options{HostOS: "linux"})
	if !rec.ManualReview {
		t.Fatal("Tier C must require manual review")
	}
	if rec.Primary != nil {
		t.Fatalf("primary = %#v, want nil", rec.Primary)
	}
}

func TestIOSOnLinuxBlocks(t *testing.T) {
	rec := Recommend(project("capacitor-app", "mobile-first", "static"), answers("android", "ios"), Options{HostOS: "linux"})
	if len(rec.Blockers) == 0 {
		t.Fatal("expected iOS build-host blocker")
	}
}

func TestOverride(t *testing.T) {
	a := answers("linux", "windows")
	a.Candidate = "electron"
	rec := Recommend(project("react", "static"), a, Options{HostOS: "linux"})
	if rec.Primary == nil || rec.Primary.ID != "electron" {
		t.Fatalf("primary = %#v, want electron override", rec.Primary)
	}
}
