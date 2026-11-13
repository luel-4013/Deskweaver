package rules

import (
	"testing"

	"github.com/luel-4013/deskweaver/internal/model"
)

func TestCatalogShape(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	stats := c.Stats()
	if stats["total"] != 65 {
		t.Fatalf("total rules = %d, want 65", stats["total"])
	}
	if stats["A"] != 15 || stats["B"] != 40 || stats["C"] != 10 {
		t.Fatalf("tier counts = A:%d B:%d C:%d, want 15/40/10", stats["A"], stats["B"], stats["C"])
	}
	if c.Hash() == "" {
		t.Fatal("empty catalog hash")
	}
}

func TestSelfTest(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, err := range c.SelfTest() {
		t.Error(err)
	}
}

func TestEvaluateEvidenceAndSupersede(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	f := NewFacts()
	f.AddFile("package.json", `{"dependencies":{"next":"15.0.0","react":"19.0.0"}}`)
	f.AddFile("next.config.js", `module.exports = {}`)
	f.AddDep("package.json", "next")
	f.AddDep("package.json", "react")
	f.AddDep("package.json", "react-dom")

	matches := c.Evaluate(f)
	if len(matches) == 0 {
		t.Fatal("no matches")
	}
	if matches[0].Rule.ID != "nextjs" {
		t.Fatalf("primary = %q, want nextjs", matches[0].Rule.ID)
	}
	for _, m := range matches {
		if m.Rule.ID == "react" || m.Rule.ID == "static-web" {
			t.Fatalf("superseded rule %q was not removed", m.Rule.ID)
		}
	}
	if len(matches[0].Evidence) == 0 {
		t.Fatal("nextjs match has no evidence")
	}
	if matches[0].Score < 70 {
		t.Fatalf("nextjs score = %d, want >= 70", matches[0].Score)
	}
}

func TestWeakSharedSignalIsNotADetection(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	f := NewFacts()
	f.AddFile("vite.config.ts", `export default {}`)
	matches := c.Evaluate(f)
	for _, m := range matches {
		if m.Rule.ID == "vue" || m.Rule.ID == "solid" {
			t.Fatalf("weak shared signal produced a false %q detection", m.Rule.ID)
		}
	}
}

func TestTierCManualReview(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	r, ok := c.RuleByID("react-native")
	if !ok {
		t.Fatal("react-native missing")
	}
	if model.Tier(r.Tier) != model.TierC {
		t.Fatalf("react-native tier = %q, want C", r.Tier)
	}
}
