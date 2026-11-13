package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/luel-4013/deskweaver/internal/app"
	"github.com/luel-4013/deskweaver/internal/model"
	"github.com/luel-4013/deskweaver/internal/security"
)

func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case r == unicode.ReplacementChar:
			return '?'
		case r < 32 || r == 127:
			return -1
		case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			return -1
		default:
			return r
		}
	}, s)
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

func printProject(w io.Writer, p *model.Project) {
	fmt.Fprintf(w, "Deskweaver scan\n")
	fmt.Fprintf(w, "  Project: %s\n", safeText(p.Name))
	fmt.Fprintf(w, "  Root:    %s\n", safeText(p.Root))
	fmt.Fprintf(w, "  Files:   %d scanned, %d skipped", p.ScannedFiles, p.SkippedFiles)
	if p.Truncated {
		fmt.Fprintf(w, " (truncated)")
	}
	fmt.Fprintln(w)
	if p.Monorepo {
		fmt.Fprintf(w, "  Monorepo: yes")
		if len(p.Workspaces) > 0 {
			fmt.Fprintf(w, " (%s)", safeText(strings.Join(p.Workspaces, ", ")))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)

	if p.Primary == nil {
		fmt.Fprintln(w, "No known framework matched. A manual profile is required.")
	} else {
		primary := p.Primary
		fmt.Fprintf(w, "Primary: %s", safeText(primary.Name))
		if primary.Version != "" {
			fmt.Fprintf(w, " %s", safeText(primary.Version))
		}
		fmt.Fprintf(w, "\n  Tier %s, %s confidence, score %d/100\n", primary.Tier, primary.Confidence, primary.Score)
		if primary.Variant != "" {
			fmt.Fprintf(w, "  Variant: %s\n", safeText(primary.Variant))
		}
		if primary.DefaultTarget != "" {
			fmt.Fprintf(w, "  Framework default: %s\n", safeText(primary.DefaultTarget))
		}
		if len(primary.Capabilities) > 0 {
			fmt.Fprintf(w, "  Capabilities: %s\n", safeText(strings.Join(primary.Capabilities, ", ")))
		}
		if primary.Notes != "" {
			fmt.Fprintf(w, "  Note: %s\n", safeText(primary.Notes))
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Evidence:")
		for _, ev := range primary.Evidence {
			path := ev.Path
			if path == "" {
				path = "(project)"
			}
			detail := ev.Detail
			if detail == "" {
				detail = ev.Kind
			}
			fmt.Fprintf(w, "  - %s: %s — %s (weight %d)\n", safeText(ev.Kind), safeText(path), safeText(detail), ev.Weight)
		}
	}
	if len(p.Detections) > 1 {
		fmt.Fprintln(w)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "Other detections:\tTier\tConfidence\tScore\tLanguage")
		for _, d := range p.Detections[1:] {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", safeText(d.Name), d.Tier, d.Confidence, d.Score, safeText(d.Language))
		}
		_ = tw.Flush()
	}
	if len(p.Warnings) > 0 {
		fmt.Fprintln(w, "\nWarnings:")
		for _, warning := range p.Warnings {
			fmt.Fprintf(w, "  - %s\n", safeText(warning))
		}
	}
	if len(p.Unknowns) > 0 {
		fmt.Fprintln(w, "\nUnknowns:")
		for _, unknown := range p.Unknowns {
			fmt.Fprintf(w, "  - %s\n", safeText(unknown))
		}
	}
	fmt.Fprintln(w, "\nRead-only scan. No project code was executed and no project file was written.")
}

func printPlan(w io.Writer, res *app.Result) {
	plan := res.Plan
	fmt.Fprintf(w, "Deskweaver plan\n")
	fmt.Fprintf(w, "  Project:    %s\n", safeText(plan.Project.Name))
	if plan.Project.Primary != nil {
		d := plan.Project.Primary
		fmt.Fprintf(w, "  Detected:   %s (Tier %s, %s confidence, %d/100)\n", safeText(d.Name), d.Tier, d.Confidence, d.Score)
	} else {
		fmt.Fprintf(w, "  Detected:   no known framework\n")
	}
	fmt.Fprintf(w, "  Generated:  %s\n", safeText(plan.GeneratedAt))
	fmt.Fprintf(w, "  Plan hash:  %s\n", plan.PlanHash)
	fmt.Fprintf(w, "  Rules:      %s (%s)\n", safeText(plan.RulesVersion), plan.RulesHash)
	fmt.Fprintln(w)

	rec := plan.Recommendation
	fmt.Fprintln(w, "Recommendation")
	if rec.Primary == nil {
		fmt.Fprintln(w, "  None. Manual review is required before choosing a conversion path.")
	} else {
		fmt.Fprintf(w, "  Primary:      %s (%d/100)\n", safeText(rec.Primary.Name), rec.Primary.Score)
		if rec.Fallback != nil {
			fmt.Fprintf(w, "  Fallback:     %s (%d/100)\n", safeText(rec.Fallback.Name), rec.Fallback.Score)
		}
		fmt.Fprintf(w, "  Architecture: %s\n", safeText(rec.Architecture))
		fmt.Fprintf(w, "  Targets:      %s\n", safeText(strings.Join(rec.RequestedTargets, ", ")))
		if rec.Sensitivity != "" {
			fmt.Fprintf(w, "  Judgment:     %s\n", safeText(rec.Sensitivity))
		}
	}
	if len(rec.Blockers) > 0 {
		fmt.Fprintln(w, "\nBlockers")
		for _, b := range rec.Blockers {
			fmt.Fprintf(w, "  - %s\n", safeText(b))
		}
	}

	if len(rec.OSMatrix) > 0 {
		fmt.Fprintln(w, "\nOS support (S0 unsupported … S4 hardened/distribution-ready; * requested)")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  OS\tLevel\tFormats\tNotes")
		for _, s := range rec.OSMatrix {
			marker := ""
			if containsFold(rec.RequestedTargets, s.OS) {
				marker = " *"
			}
			fmt.Fprintf(tw, "  %s%s\tS%d\t%s\t%s\n", titleOS(s.OS), marker, s.Level, safeText(strings.Join(s.Formats, ", ")), safeText(s.Notes))
		}
		_ = tw.Flush()
	}

	if len(rec.Reasons) > 0 {
		fmt.Fprintln(w, "\nWhy")
		for _, reason := range rec.Reasons {
			fmt.Fprintf(w, "  - %s\n", safeText(reason))
		}
	}
	if len(rec.Tradeoffs) > 0 {
		fmt.Fprintln(w, "\nTrade-offs and explicit risks")
		for _, t := range rec.Tradeoffs {
			fmt.Fprintf(w, "  - %s\n", safeText(t))
		}
	}
	if len(rec.Rejected) > 0 {
		fmt.Fprintln(w, "\nAlternatives considered")
		for _, r := range rec.Rejected {
			fmt.Fprintf(w, "  - %s (%d/100): %s\n", safeText(r.Name), r.Score, safeText(r.Reason))
		}
	}

	fmt.Fprintln(w, "\nThreat model")
	fmt.Fprintf(w, "  Profile:     %s\n", safeText(plan.Security.Profile))
	fmt.Fprintf(w, "  Sensitivity: %s\n", safeText(plan.Security.ThreatModel.Sensitivity))
	fmt.Fprintf(w, "  Input:       %s\n", untrustedText(plan.Security.ThreatModel.UntrustedInput))
	fmt.Fprintf(w, "  Network:     %s\n", safeText(plan.Security.ThreatModel.Network))
	fmt.Fprintf(w, "  Privilege:   %s\n", safeText(plan.Security.ThreatModel.Privilege))
	fmt.Fprintf(w, "  Controls:    %s\n", safeText(security.Summary(plan.Security)))
	required := 0
	for _, c := range plan.Security.Controls {
		if c.Status != "required" {
			continue
		}
		fmt.Fprintf(w, "    - %s %s\n", safeText(c.ID), safeText(c.Name))
		required++
	}
	if required == 0 {
		fmt.Fprintln(w, "    (no required controls; review recommended controls in the plan)")
	}

	fmt.Fprintln(w, "\nHost")
	if len(res.Missing) > 0 {
		fmt.Fprintf(w, "  Missing required: %s\n", safeText(strings.Join(res.Missing, ", ")))
	} else if len(plan.Host.Tools) > 0 {
		fmt.Fprintln(w, "  Required dependencies found (versions in the full plan).")
	} else {
		fmt.Fprintln(w, "  No dependency requirements declared by the recommendation.")
	}
	for _, warning := range plan.Host.Warnings {
		fmt.Fprintf(w, "  - %s\n", safeText(warning))
	}

	fmt.Fprintln(w, "\nKit")
	if res.KitDir == "" {
		fmt.Fprintln(w, "  Not generated (plan-only run).")
	} else {
		fmt.Fprintf(w, "  Directory: %s\n", safeText(res.KitDir))
		fmt.Fprintf(w, "  Files:     %d\n", len(res.KitFiles))
		if res.KitSkipped != "" {
			fmt.Fprintf(w, "  Note:      %s\n", safeText(res.KitSkipped))
		}
	}
	fmt.Fprintln(w, "\nReview-only: no generated file was executed or applied. Re-run after any dependency or threat-model change.")
	if len(rec.Blockers) > 0 || rec.ManualReview {
		fmt.Fprintln(w, "Exit status: 2 (blockers remain).")
	} else if len(res.Missing) > 0 {
		fmt.Fprintln(w, "Exit status: 3 (missing host dependencies).")
	}
}

func untrustedText(v bool) string {
	if v {
		return "untrusted/hostile"
	}
	return "trusted"
}

func containsFold(xs []string, want string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, want) {
			return true
		}
	}
	return false
}

func printHost(w io.Writer, host model.Host, missing []string) {
	fmt.Fprintf(w, "Deskweaver doctor\n")
	fmt.Fprintf(w, "  Host:    %s/%s\n", host.OS, host.Arch)
	if host.Distro != "" {
		fmt.Fprintf(w, "  Distro:  %s", safeText(host.Distro))
		if host.Version != "" {
			fmt.Fprintf(w, " %s", safeText(host.Version))
		}
		fmt.Fprintln(w)
	}
	if host.Kernel != "" {
		fmt.Fprintf(w, "  Kernel:  %s\n", safeText(host.Kernel))
	}
	if host.Session != "" {
		fmt.Fprintf(w, "  Session: %s\n", safeText(host.Session))
	}
	if host.PackageManager != "" {
		fmt.Fprintf(w, "  Package: %s\n", safeText(host.PackageManager))
	}
	if len(host.Tools) == 0 {
		fmt.Fprintln(w, "\nNo tool requirements were probed.")
	} else {
		fmt.Fprintln(w)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  Tool\tStatus\tRequired\tVersion/Detail")
		for _, t := range host.Tools {
			status := "missing"
			if t.Found {
				status = "found"
			}
			detail := t.Version
			if detail == "" {
				detail = t.Detail
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", safeText(t.Name), status, yesNo(t.Required), safeText(detail))
		}
		_ = tw.Flush()
	}
	if len(host.Webviews) > 0 {
		fmt.Fprintln(w, "\nWebView runtime")
		for _, webview := range host.Webviews {
			status := "missing"
			if webview.Found {
				status = "found"
			}
			fmt.Fprintf(w, "  %s: %s", safeText(webview.Name), status)
			if webview.Version != "" {
				fmt.Fprintf(w, " (%s)", safeText(webview.Version))
			}
			if webview.Detail != "" {
				fmt.Fprintf(w, " — %s", safeText(webview.Detail))
			}
			fmt.Fprintln(w)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(w, "\nMissing required: %s\n", safeText(strings.Join(missing, ", ")))
	}
	for _, c := range host.Checks {
		if c.Status == "ok" || c.Status == "info" {
			continue
		}
		fmt.Fprintf(w, "\n[%s] %s: %s\n", safeText(c.Status), safeText(c.Name), safeText(c.Detail))
		if c.Install != "" {
			fmt.Fprintf(w, "  Install guidance (review; not executed): %s\n", safeText(c.Install))
		}
		if c.Verify != "" {
			fmt.Fprintf(w, "  Verify: %s\n", safeText(c.Verify))
		}
	}
	if len(host.Warnings) > 0 {
		fmt.Fprintln(w, "\nWarnings")
		for _, warning := range host.Warnings {
			fmt.Fprintf(w, "  - %s\n", safeText(warning))
		}
	}
	fmt.Fprintln(w, "\nNo installs, elevation, project-code execution, or project writes were performed.")
	if len(missing) > 0 {
		fmt.Fprintf(w, "Exit status: %d (missing required host dependencies).\n", exitMissingDeps)
	}
}

func printTargets(w io.Writer, views []targetView, requested []string) {
	fmt.Fprintln(w, "Deskweaver target matrix")
	fmt.Fprintln(w, "S0 unsupported · S1 experimental · S2 caveats · S3 supported/tested · S4 hardened")
	if len(requested) > 0 {
		fmt.Fprintf(w, "Requested targets marked with *: %s\n", safeText(strings.Join(requested, ", ")))
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "Technology\tKind\tLinux\tWindows\tmacOS\tAndroid\tiOS")
	for _, v := range views {
		var cells []string
		for _, osName := range []string{"linux", "windows", "macos", "android", "ios"} {
			level := 0
			for _, entry := range v.OS {
				if entry.OS == osName {
					level = entry.Level
					break
				}
			}
			cell := fmt.Sprintf("S%d", level)
			if containsFold(requested, osName) {
				cell += "*"
			}
			cells = append(cells, cell)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", safeText(v.Name), safeText(v.Kind), strings.Join(cells, "\t"))
	}
	_ = tw.Flush()
	fmt.Fprintln(w, "\nSupport levels are engineering judgments, not vendor guarantees.")
	fmt.Fprintln(w, "Use `deskweaver explain <id>` for requirements, trade-offs, formats, and per-OS notes.")
}

func printRuleExplain(w io.Writer, out explainRule) {
	rule := out.Rule
	fmt.Fprintf(w, "Rule: %s — %s\n", safeText(rule.ID), safeText(rule.Name))
	fmt.Fprintf(w, "  Tier:           %s\n", rule.Tier)
	fmt.Fprintf(w, "  Language:       %s\n", safeText(rule.Language))
	fmt.Fprintf(w, "  Default target: %s\n", safeText(rule.DefaultTarget))
	fmt.Fprintf(w, "  Priority:       %d\n", rule.Priority)
	if len(rule.Capabilities) > 0 {
		fmt.Fprintf(w, "  Capabilities:   %s\n", safeText(strings.Join(rule.Capabilities, ", ")))
	}
	if rule.Notes != "" {
		fmt.Fprintf(w, "  Notes:          %s\n", safeText(rule.Notes))
	}
	if len(rule.Supersedes) > 0 {
		fmt.Fprintf(w, "  Supersedes:     %s\n", safeText(strings.Join(rule.Supersedes, ", ")))
	}
	fmt.Fprintln(w, "\nSignals (declarative; evaluated read-only):")
	for _, sig := range rule.Signals {
		var detail []string
		if sig.Path != "" {
			detail = append(detail, "path="+sig.Path)
		}
		if sig.Manifest != "" {
			detail = append(detail, "manifest="+sig.Manifest)
		}
		if sig.Name != "" {
			detail = append(detail, "name="+sig.Name)
		}
		if sig.Pattern != "" {
			detail = append(detail, "pattern="+sig.Pattern)
		}
		fmt.Fprintf(w, "  - %s %s (weight %d)\n", safeText(sig.Kind), safeText(strings.Join(detail, " ")), sig.Weight)
	}
	if out.Project != nil {
		fmt.Fprintln(w, "\nMatched evidence:")
		if len(out.Evidence) == 0 {
			fmt.Fprintln(w, "  This rule did not match the scanned project.")
		} else {
			fmt.Fprintf(w, "  Score: %d/100\n", out.MatchedScore)
			for _, ev := range out.Evidence {
				fmt.Fprintf(w, "  - %s: %s — %s (weight %d)\n", safeText(ev.Kind), safeText(ev.Path), safeText(ev.Detail), ev.Weight)
			}
		}
	}
	if rule.Tier == string(model.TierC) {
		fmt.Fprintln(w, "\nTier C: detection only. No automatic recommendation is allowed.")
	}
}

func printCandidateExplain(w io.Writer, v targetView) {
	fmt.Fprintf(w, "%s [%s]\n", safeText(v.Name), safeText(v.ID))
	fmt.Fprintf(w, "  Kind:         %s\n", safeText(v.Kind))
	fmt.Fprintf(w, "  Architecture: %s\n", safeText(v.Architecture))
	fmt.Fprintf(w, "  Security:     %s\n", safeText(v.SecurityNote))
	fmt.Fprintf(w, "  Scores:       security %d, feature %d, platform %d, effort %d, maintenance %d, size %d\n",
		v.Security, v.FeatureBase, v.Platform, v.Effort, v.Maintenance, v.Size)
	fmt.Fprintln(w, "\nOS support (S0 unsupported … S4 hardened/distribution-ready):")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  OS\tLevel\tFormats\tNotes")
	for _, s := range v.OS {
		fmt.Fprintf(tw, "  %s\tS%d\t%s\t%s\n", titleOS(s.OS), s.Level, safeText(strings.Join(s.Formats, ", ")), safeText(s.Notes))
	}
	_ = tw.Flush()
	if len(v.Requires) > 0 {
		fmt.Fprintf(w, "\nRequires: %s\n", safeText(strings.Join(v.Requires, ", ")))
	}
	if len(v.Tradeoffs) > 0 {
		fmt.Fprintln(w, "\nTrade-offs and risks:")
		for _, t := range v.Tradeoffs {
			fmt.Fprintf(w, "  - %s\n", safeText(t))
		}
	}
}

const helpText = `Deskweaver — Linux-first conversion advisor for local web projects.

Deskweaver scans a project read-only, detects its framework, recommends a
desktop/mobile conversion technology with S0–S4 OS support levels, checks host
dependencies, and generates a review-only security and conversion kit.

Usage:
  deskweaver                          Interactive wizard (TTY only)
  deskweaver plan [path]              Recommendation, plan, and review kit
  deskweaver scan [path]              Detect only; print the project profile
  deskweaver bundle [plan.json]       Regenerate the kit from an existing plan
  deskweaver doctor                   Host readiness checks
  deskweaver targets                  Technology/platform support matrix
  deskweaver explain <id> [path]      Rule or candidate evidence and reasoning
  deskweaver rules verify             Verify the embedded rule pack
  deskweaver rules list               List installed rule packs
  deskweaver rules test               Run the rule self-test corpus
  deskweaver self-check               Verify the installed binary's data catalogs
  deskweaver version                  Print version and build metadata

Common flags (before or after positionals):
  --json                 Stable JSON on stdout; errors as JSON on stderr
  --answers <file>       Replay a deskweaver.answers/v1 YAML file
  --no-input             Non-interactive; fail instead of prompting
  --target <csv>         linux,windows,macos,android,ios
  --format <csv>         flatpak,appimage,deb,rpm,tarball,snap,nsis,msi,
                         portable,msix,dmg,app,pkg,apk,aab,ipa
  --profile <name>       baseline|hardened|airgap|hostile-input|privileged-service
  --sensitivity <name>   public|internal|confidential|regulated
  --untrusted-input      Treat application input as hostile
  --network <name>       offline|allowlist|open
  --privilege <name>     none|raw-sockets|usb|privileged-service|kernel
  --candidate <id>       Explicit technology override (deskweaver targets)
  --out <dir>            Kit output directory (default: deskweaver-out)
  --no-kit               Produce the plan without generating a kit
  --force                Replace a non-empty kit with a timestamped backup
  --redact               Remove absolute paths from the plan output
  --offline              Request offline behavior; no network is used anyway
  --no-exec              Accepted no-op: advisor-only mode never executes
  --max-files <n>        Bound the read-only scan (1–1000000)
  --no-color             Disable wizard color
  --weight <key=value>   Reserved; rejected rather than silently ignored
  --distro <name>        Doctor guidance target, e.g. ubuntu-22.04
  --workspace <path>     Analyze one monorepo workspace
  --help, -h             Show this help
  --version, -V          Show version

Safety contract:
  - No installs, no elevation, no project writes, no project-code execution.
  - The only write is the generated kit, staged and committed atomically.
  - Existing non-empty kit directories are refused unless --force, which moves
    them to a timestamped backup instead of deleting them.
  - support levels are engineering judgments, not vendor guarantees.
  - The development rule pack is integrity-checked but not cryptographically
    signed; do not describe it as signed.

Exit codes:
  0   success
  1   invalid usage or unsafe request
  2   project blockers remain (manual review / no conversion path)
  3   missing required host dependencies
  4   unsupported target or target/format mismatch
  5   internal error
  130 cancelled by the user

Examples:
  deskweaver
  deskweaver scan ~/repos/app
  deskweaver plan ~/repos/app
  deskweaver plan --no-input --target linux,windows --profile hardened .
  deskweaver plan --answers deskweaver-out/answers.yaml
  deskweaver bundle deskweaver-out/plan.json --out ./review-kit
  deskweaver doctor --target linux --distro ubuntu-22.04
  deskweaver explain react ~/repos/app
`
