package recommend

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/luel-4013/deskweaver/internal/model"
)

var osOrder = []string{"linux", "windows", "macos", "android", "ios"}

type scoredCandidate struct {
	c        Candidate
	total    int
	feature  int
	platform int
	eligible bool
	why      string
}

// Options carries context that is not part of the project profile.
type Options struct {
	HostOS string
}

// Recommend scores the candidate catalog against the detected project and the
// user's threat model. It is deterministic for the same inputs.
func Recommend(p *model.Project, ans model.Answers, opts Options) model.Recommendation {
	targets, invalid := normalizeTargets(ans.Targets)
	rec := model.Recommendation{RequestedTargets: targets}
	if len(invalid) > 0 {
		rec.Blockers = append(rec.Blockers, "Unsupported target(s): "+strings.Join(invalid, ", ")+". Supported: linux, windows, macos, android, ios.")
	}
	if p == nil || p.Primary == nil {
		rec.ManualReview = true
		rec.Reasons = []string{"No framework was detected with enough confidence to recommend a conversion path."}
		rec.Blockers = append(rec.Blockers, "Manual profile required before planning.")
		return rec
	}
	primary := p.Primary
	rec.Unknowns = append(rec.Unknowns, p.Unknowns...)
	if primary.Tier == model.TierC {
		rec.ManualReview = true
		rec.Reasons = []string{
			fmt.Sprintf("%s is a Tier C (heuristic) detection.", primary.Name),
			"Tier C frameworks are detection-only. A manual review must establish the app shape before any target is recommended.",
		}
		rec.Blockers = append(rec.Blockers, "Tier C framework: manual review required; no automatic recommendation or conversion kit.")
		return rec
	}

	roles := rolesFor(primary, ans)
	all := make([]scoredCandidate, 0, len(All()))
	for _, c := range All() {
		total, feature, platform, eligible, why := scoreCandidate(c, roles, targets)
		all = append(all, scoredCandidate{c: c, total: total, feature: feature, platform: platform, eligible: eligible, why: why})
	}

	overrideID := ""
	if ans.Candidate != "" {
		found := false
		for _, s := range all {
			if s.c.ID == ans.Candidate {
				found = true
				if s.eligible {
					overrideID = ans.Candidate
				} else {
					rec.Blockers = append(rec.Blockers, fmt.Sprintf("Requested candidate %q is not viable: %s", ans.Candidate, s.why))
				}
				break
			}
		}
		if !found {
			rec.Blockers = append(rec.Blockers, fmt.Sprintf("Unknown candidate override %q.", ans.Candidate))
		}
	}

	sort.SliceStable(all, func(i, j int) bool {
		if overrideID != "" {
			if all[i].c.ID == overrideID && all[j].c.ID != overrideID {
				return true
			}
			if all[j].c.ID == overrideID && all[i].c.ID != overrideID {
				return false
			}
		}
		if all[i].eligible != all[j].eligible {
			return all[i].eligible
		}
		return all[i].total > all[j].total
	})

	var viable []scoredCandidate
	for _, s := range all {
		if s.eligible {
			viable = append(viable, s)
		}
	}
	if len(viable) == 0 {
		rec.ManualReview = true
		rec.Reasons = append(rec.Reasons, "No candidate supports the requested target set.")
		rec.Blockers = append(rec.Blockers, "No viable conversion technology for the requested targets.")
		return rec
	}

	chosen := viable[0]
	rec.Primary = &model.RankedCandidate{
		ID:     chosen.c.ID,
		Name:   chosen.c.Name,
		Score:  chosen.total,
		Reason: fmt.Sprintf("%s scores %d/100 for %s.", chosen.c.Name, chosen.total, strings.Join(targets, "+")),
	}
	if overrideID != "" && chosen.c.ID == overrideID {
		rec.Primary.Reason = "Explicit user override; the score is shown for comparison."
	}
	if len(viable) > 1 {
		fb := viable[1]
		rec.Fallback = &model.RankedCandidate{
			ID:     fb.c.ID,
			Name:   fb.c.Name,
			Score:  fb.total,
			Reason: fmt.Sprintf("Fallback: %s scores %d/100.", fb.c.Name, fb.total),
		}
	}
	var rejected []model.RankedCandidate
	for _, s := range all {
		if len(rejected) >= 4 {
			break
		}
		if s.c.ID == chosen.c.ID || (rec.Fallback != nil && s.c.ID == rec.Fallback.ID) {
			continue
		}
		if !s.eligible {
			rejected = append(rejected, model.RankedCandidate{ID: s.c.ID, Name: s.c.Name, Score: s.total, Reason: s.why})
		}
	}
	for _, s := range all {
		if len(rejected) >= 4 {
			break
		}
		if s.c.ID == chosen.c.ID || (rec.Fallback != nil && s.c.ID == rec.Fallback.ID) {
			continue
		}
		if s.eligible {
			rejected = append(rejected, model.RankedCandidate{
				ID: s.c.ID, Name: s.c.Name, Score: s.total,
				Reason: "Lower weighted score for this project and target set.",
			})
		}
	}
	rec.Rejected = rejected

	rec.Reasons = append(rec.Reasons,
		fmt.Sprintf("Detected %s with %s confidence (Tier %s, score %d/100).",
			detectionLabel(primary), primary.Confidence, primary.Tier, primary.Score),
		fmt.Sprintf("Requested targets: %s. %s supports %s.",
			strings.Join(targets, ", "), chosen.c.Name, supportSummary(chosen.c, targets)),
		"Security model: "+chosen.c.SecurityNote,
	)
	if primary.Tier == model.TierB {
		rec.Reasons = append(rec.Reasons, "This is a Tier B profile: detection is standard, not deep. Verify the app shape before building.")
	}
	if ans.UntrustedInput {
		rec.Reasons = append(rec.Reasons, "Hostile input is in scope; the recommendation favors process isolation, a patchable engine, and a narrow parser boundary.")
	}
	if isPrivileged(ans.Privilege) {
		rec.Reasons = append(rec.Reasons, "Privilege is split from the UI: the service is small and auditable, and the UI stays unprivileged.")
	}
	if chosen.c.ID == "modernize" {
		rec.Reasons = append(rec.Reasons, "Packaging this stack as-is would ship a known-risk runtime. Modernize first, then re-run Deskweaver.")
	}
	if chosen.c.ID == "container" {
		rec.Reasons = append(rec.Reasons, "This is a server/CMS shape, not a desktop app. A container or remote PWA is the honest delivery model.")
	}

	rec.Tradeoffs = append(rec.Tradeoffs, chosen.c.Tradeoffs...)
	if primary.Notes != "" {
		rec.Tradeoffs = append(rec.Tradeoffs, "Framework note: "+primary.Notes)
	}
	rec.Architecture = chosen.c.Architecture
	rec.OSMatrix = supportMatrix(chosen.c)
	rec.Sensitivity = sensitivityNote(chosen, viable)
	rec.Unknowns = dedupe(append(rec.Unknowns, "Mobile support is a separate delivery plan, not desktop parity."))
	rec.ManualReview = false

	if p.Monorepo && ans.Workspace == "" {
		rec.Blockers = append(rec.Blockers, "Monorepo/workspace detected: select a workspace before generating a conversion kit.")
	}
	if contains(targets, "ios") && opts.HostOS != "" && opts.HostOS != "darwin" {
		rec.Blockers = append(rec.Blockers, "iOS builds require macOS and Xcode; this host cannot build iOS.")
	}
	if chosen.c.ID == "modernize" {
		rec.Blockers = append(rec.Blockers, "No conversion kit: modernization is required first.")
	}
	if chosen.c.ID == "container" {
		rec.Blockers = append(rec.Blockers, "No desktop conversion kit: use a container or remote PWA plan.")
	}
	return rec
}

func rolesFor(d *model.Detection, ans model.Answers) []string {
	caps := make(map[string]bool)
	for _, c := range d.Capabilities {
		caps[strings.ToLower(c)] = true
	}
	var roles []string
	switch {
	case caps["legacy"]:
		roles = append(roles, "legacy")
	case caps["do-not-package"]:
		roles = append(roles, "do-not-package")
	case caps["mobile-first"]:
		roles = append(roles, "mobile")
	default:
		switch {
		case caps["laravel"]:
			roles = append(roles, "laravel")
		case caps["php"] && caps["server"]:
			roles = append(roles, "php-server")
		case caps["python"] && caps["server"]:
			roles = append(roles, "python-server")
		case caps["ruby"] && caps["server"]:
			roles = append(roles, "ruby-server")
		case caps["go"] && caps["server"]:
			roles = append(roles, "go-server")
		case caps["dotnet"] && caps["server"]:
			roles = append(roles, "dotnet-server")
		case caps["java"] && caps["server"]:
			roles = append(roles, "java-server")
		case caps["rust"] && caps["server"]:
			roles = append(roles, "rust-server")
		case caps["node"] && caps["server"]:
			roles = append(roles, "node-server")
		case caps["server"]:
			roles = append(roles, "server")
		default:
			roles = append(roles, "static")
		}
	}
	if caps["cms"] {
		roles = append(roles, "cms")
	}
	if ans.UntrustedInput {
		roles = append(roles, "hostile")
	}
	if isPrivileged(ans.Privilege) {
		roles = append(roles, "privileged")
	}
	return dedupe(roles)
}

func scoreCandidate(c Candidate, roles, targets []string) (total, feature, platform int, eligible bool, why string) {
	if len(targets) == 0 {
		targets = []string{"linux", "windows"}
	}
	for _, t := range targets {
		s, ok := c.OS[t]
		if !ok || s.Level == 0 {
			return 0, 0, 0, false, c.Name + " does not support " + t
		}
		platform += levelScore(s.Level)
	}
	platform /= len(targets)
	feature = c.FeatureBase
	if len(roles) > 0 {
		// Security-critical roles dominate the fit score. A technology that
		// merely tolerates privilege must not tie one designed for it.
		sum, weightTotal := 0, 0
		for _, role := range roles {
			weight := roleWeight(role)
			weightTotal += weight
			if w, ok := c.Roles[role]; ok {
				sum += w * weight
			} else {
				sum -= 20 * weight
			}
		}
		feature += sum / weightTotal
	}
	feature = clamp(feature, 0, 100)
	total = int(math.Round(
		0.30*float64(c.Security) +
			0.25*float64(feature) +
			0.15*float64(platform) +
			0.15*float64(c.Effort) +
			0.10*float64(c.Maintenance) +
			0.05*float64(c.Size)))
	return total, feature, platform, true, ""
}

func levelScore(level int) int {
	switch level {
	case 0:
		return 0
	case 1:
		return 25
	case 2:
		return 65
	case 3:
		return 85
	case 4:
		return 100
	default:
		return 0
	}
}

// roleWeight makes security-critical requirements decisive instead of letting
// them average away against a generic "static" role.
func roleWeight(role string) int {
	switch role {
	case "privileged", "kernel", "driver":
		return 4
	case "hostile", "legacy", "do-not-package", "cms":
		return 3
	case "mobile":
		return 2
	default:
		return 1
	}
}

func normalizeTargets(in []string) ([]string, []string) {
	if len(in) == 0 {
		in = []string{"linux", "windows"}
	}
	valid := map[string]bool{"linux": true, "windows": true, "macos": true, "android": true, "ios": true}
	seen := make(map[string]bool)
	var out, invalid []string
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		if valid[t] {
			out = append(out, t)
		} else {
			invalid = append(invalid, t)
		}
	}
	if len(out) == 0 {
		out = []string{"linux", "windows"}
	}
	return out, invalid
}

func supportSummary(c Candidate, targets []string) string {
	var parts []string
	for _, t := range targets {
		if s, ok := c.OS[t]; ok {
			parts = append(parts, fmt.Sprintf("%s S%d", titleOS(t), s.Level))
		} else {
			parts = append(parts, titleOS(t)+" S0")
		}
	}
	return strings.Join(parts, ", ")
}

func supportMatrix(c Candidate) []model.OSSupport {
	out := make([]model.OSSupport, 0, len(osOrder))
	for _, os := range osOrder {
		if s, ok := c.OS[os]; ok {
			s.Label = model.OSLabel(s.Level)
			out = append(out, s)
		} else {
			out = append(out, model.OSSupport{OS: os, Level: 0, Label: model.OSLabel(0)})
		}
	}
	return out
}

func sensitivityNote(chosen scoredCandidate, viable []scoredCandidate) string {
	if len(viable) < 2 {
		return "No close alternative supports this target set."
	}
	diff := chosen.total - viable[1].total
	if diff <= 5 {
		return fmt.Sprintf("Close call: %s leads %s by only %d points. A different security-versus-effort requirement, or a need for bundled Chromium, could flip the decision.",
			chosen.c.Name, viable[1].c.Name, diff)
	}
	return fmt.Sprintf("%s leads %s by %d points. The main trade-off is security/compatibility versus effort and bundle size.",
		chosen.c.Name, viable[1].c.Name, diff)
}

func isPrivileged(p string) bool {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "privileged-service", "privileged", "kernel", "driver":
		return true
	default:
		return false
	}
}

func detectionLabel(d *model.Detection) string {
	if d.Version == "" {
		return d.Name
	}
	version := strings.TrimSpace(d.Version)
	if version == "" {
		return d.Name
	}
	if !strings.HasPrefix(version, "v") && !strings.ContainsAny(version[:1], "^~<>=!") {
		version = "v" + version
	}
	return d.Name + " " + version
}

func titleOS(s string) string {
	switch s {
	case "linux":
		return "Linux"
	case "windows":
		return "Windows"
	case "macos":
		return "macOS"
	case "android":
		return "Android"
	case "ios":
		return "iOS"
	default:
		return s
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func dedupe(xs []string) []string {
	seen := make(map[string]bool)
	out := xs[:0]
	for _, x := range xs {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}
