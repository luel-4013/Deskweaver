package security

import (
	"strings"
	"testing"

	"github.com/luel-4013/deskweaver/internal/model"
)

func planFor(candidate string, caps []string, ans model.Answers) model.SecurityPlan {
	p := &model.Project{
		Name: "demo",
		Primary: &model.Detection{
			RuleID: "demo", Name: "Demo", Tier: model.TierA,
			Language: "node", Capabilities: caps,
		},
		Capabilities: caps,
	}
	rec := model.Recommendation{Primary: &model.RankedCandidate{ID: candidate, Name: candidate}}
	return Build(p, rec, ans)
}

func hasControl(plan model.SecurityPlan, id string) bool {
	for _, c := range plan.Controls {
		if c.ID == id {
			return true
		}
	}
	return false
}

func TestTauriHardenedControls(t *testing.T) {
	ans := model.Answers{
		Targets: []string{"linux", "windows"}, Profile: "hardened",
		Sensitivity: "confidential", Network: "offline", Privilege: "none", Formats: []string{"flatpak"},
	}
	plan := planFor("tauri", []string{"static"}, ans)
	for _, id := range []string{"SEC-CSP-01", "SEC-NAV-01", "SEC-SHELL-02", "SEC-SUPPLY-01", "SEC-SIGN-01", "SEC-DATA-01", "SEC-LOG-01", "SEC-NET-01", "SEC-SANDBOX-01"} {
		if !hasControl(plan, id) {
			t.Errorf("missing control %s", id)
		}
	}
	if hasControl(plan, "SEC-SHELL-01") {
		t.Error("Tauri plan must not include Electron control")
	}
	if len(plan.ResidualRisks) < 8 {
		t.Fatalf("residual risks = %d, want at least 8", len(plan.ResidualRisks))
	}
	if plan.Profile != "hardened" || plan.ThreatModel.Network != "offline" {
		t.Fatalf("bad normalized plan: %#v", plan)
	}
}

func TestElectronHostileInput(t *testing.T) {
	ans := model.Answers{
		Targets: []string{"linux", "windows"}, Profile: "hostile-input",
		Sensitivity: "regulated", Network: "offline", Privilege: "none", UntrustedInput: true,
	}
	plan := planFor("electron", []string{"static"}, ans)
	if !hasControl(plan, "SEC-SHELL-01") || !hasControl(plan, "SEC-LOG-01") {
		t.Fatal("electron hostile-input plan lacks shell or log controls")
	}
	joined := strings.Join(plan.ResidualRisks, " ")
	if !strings.Contains(joined, "disposable VM") {
		t.Fatal("hostile-input residual risks should mention disposable VM")
	}
}

func TestPrivilegedServiceControls(t *testing.T) {
	ans := model.Answers{
		Targets: []string{"linux"}, Profile: "privileged-service",
		Sensitivity: "internal", Network: "offline", Privilege: "privileged-service",
	}
	plan := planFor("tauri", []string{"static"}, ans)
	if !hasControl(plan, "SEC-PRIV-01") {
		t.Fatal("missing privilege control")
	}
	for _, c := range plan.Controls {
		if c.ID == "SEC-LOCAL-02" && c.Status != "required" {
			t.Fatalf("privileged local socket status = %q, want required", c.Status)
		}
	}
}

func TestModernizeStopsAtModernization(t *testing.T) {
	ans := model.Answers{
		Targets: []string{"linux", "windows"}, Profile: "baseline",
		Sensitivity: "internal", Network: "open", Privilege: "none",
	}
	plan := planFor("modernize", []string{"legacy", "server"}, ans)
	if hasControl(plan, "SEC-CSP-01") || hasControl(plan, "SEC-SHELL-01") {
		t.Fatal("modernize plan must not contain shell controls")
	}
	joined := strings.Join(plan.ResidualRisks, " ")
	if !strings.Contains(joined, "EOL") {
		t.Fatal("modernize residual risks should mention EOL")
	}
}

func TestNoDuplicateControlIDs(t *testing.T) {
	ans := model.Answers{
		Targets: []string{"linux"}, Profile: "airgap",
		Sensitivity: "confidential", Network: "offline", Privilege: "none",
	}
	plan := planFor("container", []string{"cms", "server"}, ans)
	seen := make(map[string]bool)
	for _, c := range plan.Controls {
		if seen[c.ID] {
			t.Fatalf("duplicate control %s", c.ID)
		}
		seen[c.ID] = true
	}
}
