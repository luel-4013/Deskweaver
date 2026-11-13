package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/luel-4013/deskweaver/internal/app"
	"github.com/luel-4013/deskweaver/internal/doctor"
	"github.com/luel-4013/deskweaver/internal/model"
	"github.com/luel-4013/deskweaver/internal/recommend"
	"github.com/luel-4013/deskweaver/internal/rules"
	"github.com/luel-4013/deskweaver/internal/scan"
)

func readPlan(path string) (*model.Plan, error) {
	abs, err := filepathAbs(path)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("plan file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("plan file is not a regular file: %s", abs)
	}
	if st.Size() > 32<<20 {
		return nil, errors.New("plan file is larger than 32 MiB")
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read plan file: %w", err)
	}
	var plan model.Plan
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&plan); err != nil {
		return nil, fmt.Errorf("parse plan file: %w", err)
	}
	if plan.Schema != app.Schema {
		return nil, fmt.Errorf("unsupported plan schema %q; expected %q", plan.Schema, app.Schema)
	}
	if plan.Project.Schema == "" {
		return nil, errors.New("plan file is missing project data")
	}
	return &plan, nil
}

func filepathAbs(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	return abs, nil
}

var standardDoctorTools = []string{
	"node", "npm", "rustc", "cargo", "go", "python3", "php", "composer",
	"git", "pkg-config", "webkit2gtk-4.1", "container-runtime",
}

func cmdDoctor(ctx context.Context, inv *invocation, s *streams) (int, error) {
	if len(inv.args) != 0 {
		return exitUsage, failf(exitUsage, "doctor takes no positional arguments")
	}
	if err := ctx.Err(); err != nil {
		return exitCancelled, err
	}
	targetOS := strings.ToLower(strings.TrimSpace(inv.one("target")))
	distro := strings.TrimSpace(inv.one("distro"))
	if targetOS == "" && distro != "" {
		return exitUsage, failf(exitUsage, "--distro requires --target linux")
	}
	if targetOS != "" {
		targets, err := validateTargets([]string{normalizeHostTarget(targetOS)})
		if err != nil {
			return exitUnsupported, err
		}
		if len(targets) != 1 {
			return exitUsage, failf(exitUsage, "doctor accepts exactly one --target")
		}
		targetOS = normalizeHostTarget(targets[0])
		if targetOS == "android" || targetOS == "ios" {
			return exitUnsupported, failf(exitUnsupported, "doctor checks desktop build hosts; %s is not a doctor target", targetOS)
		}
		if targetOS != "linux" && distro != "" {
			return exitUsage, failf(exitUsage, "--distro is only valid with --target linux")
		}
	}
	if targetOS == "" && distro == "" && !s.json && !inv.has("no-input") && interactive(s.in, s.out) {
		picked, err := pickDoctorTarget(ctx, s)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return exitCancelled, context.Canceled
			}
			return exitUsage, err
		}
		targetOS, distro = picked.os, picked.distro
	}

	requirements := standardDoctorTools
	optional := true
	candidateID := strings.ToLower(strings.TrimSpace(inv.one("candidate")))
	if candidateID != "" {
		c, ok := recommend.ByID(candidateID)
		if !ok {
			return exitUsage, failf(exitUsage, "unknown candidate %q", candidateID)
		}
		requirements = c.Requires
		optional = false
	}
	effectiveTarget := targetOS
	if effectiveTarget == "" {
		effectiveTarget = runtime.GOOS
		if effectiveTarget == "darwin" {
			effectiveTarget = "macos"
		}
	}
	requirements = doctor.FilterRequirements(requirements, []string{effectiveTarget})
	host := doctor.Check(requirements, doctor.Options{
		Timeout:       3 * time.Second,
		HostOS:        targetOS,
		Distro:        distro,
		OptionalTools: optional,
		Offline:       flagBool(inv, "offline"),
	})
	missing := doctor.MissingRequired(host)
	code := exitOK
	if len(missing) > 0 {
		code = exitMissingDeps
	}
	if s.json {
		if err := s.encode(struct {
			Schema          string     `json:"schema"`
			Host            model.Host `json:"host"`
			MissingRequired []string   `json:"missing_required,omitempty"`
			ExitCode        int        `json:"exit_code"`
		}{Schema: "deskweaver.doctor/v1", Host: host, MissingRequired: missing, ExitCode: code}); err != nil {
			return exitInternal, err
		}
		return code, nil
	}
	printHost(s.out, host, missing)
	return code, nil
}

type doctorChoice struct {
	os     string
	distro string
}

func pickDoctorTarget(ctx context.Context, s *streams) (doctorChoice, error) {
	return pickDoctorTargetHuh(ctx, s)
}

func normalizeHostTarget(target string) string {
	switch target {
	case "macos", "darwin":
		return "macos"
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	default:
		return target
	}
}

type targetView struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Kind         string            `json:"kind"`
	Architecture string            `json:"architecture"`
	SecurityNote string            `json:"security_note"`
	Requires     []string          `json:"requires,omitempty"`
	Tradeoffs    []string          `json:"tradeoffs,omitempty"`
	Security     int               `json:"security_score"`
	FeatureBase  int               `json:"feature_score"`
	Platform     int               `json:"platform_score"`
	Effort       int               `json:"effort_score"`
	Maintenance  int               `json:"maintenance_score"`
	Size         int               `json:"size_score"`
	OS           []model.OSSupport `json:"os"`
}

func viewCandidate(c recommend.Candidate) targetView {
	osMatrix := make([]model.OSSupport, 0, 5)
	for _, name := range []string{"linux", "windows", "macos", "android", "ios"} {
		if entry, ok := c.OS[name]; ok {
			entry.Label = model.OSLabel(entry.Level)
			osMatrix = append(osMatrix, entry)
		} else {
			osMatrix = append(osMatrix, model.OSSupport{OS: name, Level: 0, Label: model.OSLabel(0)})
		}
	}
	return targetView{
		ID: c.ID, Name: c.Name, Kind: c.Kind, Architecture: c.Architecture,
		SecurityNote: c.SecurityNote, Requires: append([]string(nil), c.Requires...),
		Tradeoffs: append([]string(nil), c.Tradeoffs...),
		Security:  c.Security, FeatureBase: c.FeatureBase, Platform: c.Platform,
		Effort: c.Effort, Maintenance: c.Maintenance, Size: c.Size, OS: osMatrix,
	}
}

func cmdTargets(ctx context.Context, inv *invocation, s *streams) (int, error) {
	if len(inv.args) != 0 {
		return exitUsage, failf(exitUsage, "targets takes no positional arguments; use deskweaver explain <id> for one technology")
	}
	if err := ctx.Err(); err != nil {
		return exitCancelled, err
	}
	var requested []string
	if inv.has("target") {
		var err error
		requested, err = validateTargets(cleanValues(inv.values["target"]))
		if err != nil {
			return exitUnsupported, err
		}
	}
	all := recommend.All()
	views := make([]targetView, 0, len(all))
	for _, c := range all {
		views = append(views, viewCandidate(c))
	}
	if s.json {
		if err := s.encode(struct {
			Schema     string       `json:"schema"`
			Requested  []string     `json:"requested,omitempty"`
			Candidates []targetView `json:"candidates"`
		}{Schema: "deskweaver.targets/v1", Requested: requested, Candidates: views}); err != nil {
			return exitInternal, err
		}
		return exitOK, nil
	}
	printTargets(s.out, views, requested)
	return exitOK, nil
}

type explainRule struct {
	Schema       string           `json:"schema"`
	Kind         string           `json:"kind"`
	ID           string           `json:"id"`
	Rule         rules.Rule       `json:"rule"`
	Evidence     []model.Evidence `json:"evidence,omitempty"`
	MatchedScore int              `json:"matched_score,omitempty"`
	Project      *model.Project   `json:"project,omitempty"`
}

func cmdExplain(ctx context.Context, inv *invocation, s *streams) (int, error) {
	if len(inv.args) < 1 || len(inv.args) > 2 {
		return exitUsage, failf(exitUsage, "usage: deskweaver explain <rule-or-candidate-id> [project-path]")
	}
	if err := ctx.Err(); err != nil {
		return exitCancelled, err
	}
	id := strings.ToLower(strings.TrimSpace(inv.args[0]))
	if id == "" {
		return exitUsage, failf(exitUsage, "explain requires an id")
	}
	catalog, err := rules.Load()
	if err != nil {
		return exitInternal, err
	}
	if rule, ok := catalog.RuleByID(id); ok {
		out := explainRule{Schema: "deskweaver.explain/v1", Kind: "rule", ID: id, Rule: rule}
		if len(inv.args) == 2 {
			project, facts, err := scanForExplain(inv.args[1], inv.one("workspace"), inv)
			if err != nil {
				return exitUsage, err
			}
			out.Project = project
			for _, m := range catalog.Evaluate(facts) {
				if m.Rule.ID == id {
					out.Evidence = m.Evidence
					out.MatchedScore = m.Score
					break
				}
			}
		}
		if s.json {
			if err := s.encode(out); err != nil {
				return exitInternal, err
			}
		} else {
			printRuleExplain(s.out, out)
		}
		return exitOK, nil
	}
	if c, ok := recommend.ByID(id); ok {
		view := viewCandidate(c)
		if s.json {
			if err := s.encode(struct {
				Schema    string     `json:"schema"`
				Kind      string     `json:"kind"`
				ID        string     `json:"id"`
				Candidate targetView `json:"candidate"`
			}{Schema: "deskweaver.explain/v1", Kind: "candidate", ID: id, Candidate: view}); err != nil {
				return exitInternal, err
			}
		} else {
			printCandidateExplain(s.out, view)
		}
		return exitOK, nil
	}
	return exitUsage, failf(exitUsage, "unknown rule or candidate id %q", id)
}

func scanForExplain(path, workspace string, inv *invocation) (*model.Project, *rules.Facts, error) {
	maxFiles, err := inv.int("max-files")
	if err != nil {
		return nil, nil, failf(exitUsage, "%v", err)
	}
	if inv.has("max-files") && !validMaxFiles(maxFiles) {
		return nil, nil, failf(exitUsage, "--max-files must be between 1 and 1000000")
	}
	opts := scan.DefaultOptions()
	if maxFiles > 0 {
		opts.MaxFiles = maxFiles
	}
	opts.Workspace = workspace
	return scan.Scan(path, opts)
}

func cmdRules(ctx context.Context, inv *invocation, s *streams) (int, error) {
	if len(inv.args) != 1 {
		return exitUsage, failf(exitUsage, "usage: deskweaver rules <verify|list|test>")
	}
	if err := ctx.Err(); err != nil {
		return exitCancelled, err
	}
	catalog, err := rules.Load()
	if err != nil {
		return exitInternal, err
	}
	stats := catalog.Stats()
	switch inv.args[0] {
	case "verify":
		signed := catalog.Signature != "" && catalog.Signature != "dev-unsigned"
		out := struct {
			Schema      string `json:"schema"`
			Pack        string `json:"pack"`
			RulesSchema string `json:"rules_schema"`
			Version     string `json:"version"`
			RulesHash   string `json:"rules_hash"`
			Rules       int    `json:"rules"`
			Signature   string `json:"signature"`
			Signed      bool   `json:"signed"`
			Integrity   string `json:"integrity"`
			Note        string `json:"note"`
		}{
			Schema: "deskweaver.rules.verify/v1", Pack: "embedded", RulesSchema: catalog.Schema,
			Version: catalog.Version, RulesHash: catalog.Hash(), Rules: len(catalog.Rules),
			Signature: catalog.Signature, Signed: signed, Integrity: "sha256-of-catalog-json",
		}
		if !signed {
			out.Note = "This development build is integrity-checked by its embedded SHA-256 but is NOT cryptographically signed. Do not describe it as signed."
		} else {
			out.Note = "A signature field is present; verify it with the release tooling before trusting authenticity."
		}
		if s.json {
			if err := s.encode(out); err != nil {
				return exitInternal, err
			}
		} else {
			s.printf("Rule pack: embedded\n")
			s.printf("  Schema:     %s\n", out.RulesSchema)
			s.printf("  Version:    %s\n", out.Version)
			s.printf("  Rules:      %d (A %d, B %d, C %d)\n", out.Rules, stats["A"], stats["B"], stats["C"])
			s.printf("  SHA-256:    %s\n", out.RulesHash)
			s.printf("  Signature:  %s\n", out.Signature)
			s.printf("  Signed:     %s\n", yesNo(out.Signed))
			s.printf("\n  %s\n", out.Note)
		}
		return exitOK, nil
	case "list":
		out := struct {
			Schema string `json:"schema"`
			Packs  []struct {
				ID        string         `json:"id"`
				Schema    string         `json:"rules_schema"`
				Version   string         `json:"version"`
				Updated   string         `json:"updated"`
				Signature string         `json:"signature"`
				Hash      string         `json:"hash"`
				Stats     map[string]int `json:"stats"`
			} `json:"packs"`
		}{Schema: "deskweaver.rules.list/v1"}
		out.Packs = append(out.Packs, struct {
			ID        string         `json:"id"`
			Schema    string         `json:"rules_schema"`
			Version   string         `json:"version"`
			Updated   string         `json:"updated"`
			Signature string         `json:"signature"`
			Hash      string         `json:"hash"`
			Stats     map[string]int `json:"stats"`
		}{ID: "embedded", Schema: catalog.Schema, Version: catalog.Version, Updated: catalog.Updated,
			Signature: catalog.Signature, Hash: catalog.Hash(), Stats: stats})
		if s.json {
			if err := s.encode(out); err != nil {
				return exitInternal, err
			}
		} else {
			s.printf("Installed rule packs: 1\n")
			s.printf("  embedded  %s  schema=%s  rules=%d  signature=%s\n",
				catalog.Version, catalog.Schema, len(catalog.Rules), catalog.Signature)
			s.printf("  hash=%s\n", catalog.Hash())
			s.printf("\nOnly the embedded catalog is installed. External rule packs are not supported in this build.\n")
		}
		return exitOK, nil
	case "test":
		errs := catalog.SelfTest()
		out := struct {
			Schema   string   `json:"schema"`
			Total    int      `json:"total"`
			Passed   int      `json:"passed"`
			Failed   int      `json:"failed"`
			Failures []string `json:"failures,omitempty"`
		}{Schema: "deskweaver.rules.test/v1", Total: len(catalog.Rules), Passed: len(catalog.Rules) - len(errs), Failed: len(errs)}
		for _, e := range errs {
			out.Failures = append(out.Failures, e.Error())
		}
		if s.json {
			if err := s.encode(out); err != nil {
				return exitInternal, err
			}
		} else {
			s.printf("Rule self-test: %d/%d fired on their own seed facts\n", out.Passed, out.Total)
			for _, f := range out.Failures {
				s.printf("  FAIL %s\n", safeText(f))
			}
			if out.Failed == 0 {
				s.printf("All rules are exercisable. This checks rule syntax and firing, not detection accuracy.\n")
			}
		}
		if out.Failed > 0 {
			return exitInternal, nil
		}
		return exitOK, nil
	default:
		return exitUsage, failf(exitUsage, "unknown rules subcommand %q; use verify, list, or test", inv.args[0])
	}
}

func cmdSelfCheck(ctx context.Context, inv *invocation, s *streams) (int, error) {
	if len(inv.args) != 0 {
		return exitUsage, failf(exitUsage, "self-check takes no positional arguments")
	}
	if err := ctx.Err(); err != nil {
		return exitCancelled, err
	}
	type check struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	var checks []check
	add := func(name, status, detail string) {
		checks = append(checks, check{Name: name, Status: status, Detail: detail})
	}

	catalog, err := rules.Load()
	if err != nil {
		add("rule catalog", "fail", err.Error())
	} else {
		stats := catalog.Stats()
		add("rule catalog", "ok", fmt.Sprintf("embedded %s, schema %s, %d rules (A %d, B %d, C %d)",
			catalog.Version, catalog.Schema, len(catalog.Rules), stats["A"], stats["B"], stats["C"]))
		add("catalog hash", "ok", catalog.Hash())
		add("catalog signature", "warn", "signature="+catalog.Signature+"; integrity is checked, authenticity is not")
		errs := catalog.SelfTest()
		if len(errs) == 0 {
			add("rule self-test", "ok", fmt.Sprintf("%d/%d rules fired on seed facts", len(catalog.Rules), len(catalog.Rules)))
		} else {
			add("rule self-test", "fail", fmt.Sprintf("%d rule(s) failed", len(errs)))
			for _, e := range errs {
				add("rule self-test detail", "fail", e.Error())
			}
		}
	}
	candidates := recommend.All()
	ids := make(map[string]bool)
	candidateProblems := 0
	for _, c := range candidates {
		if c.ID == "" || c.Name == "" || ids[c.ID] {
			candidateProblems++
		}
		ids[c.ID] = true
		for _, score := range []int{c.Security, c.FeatureBase, c.Platform, c.Effort, c.Maintenance, c.Size} {
			if score < 0 || score > 100 {
				candidateProblems++
				break
			}
		}
		for _, osName := range []string{"linux", "windows", "macos", "android", "ios"} {
			if _, ok := c.OS[osName]; !ok {
				candidateProblems++
				break
			}
		}
	}
	if candidateProblems == 0 {
		add("candidate catalog", "ok", fmt.Sprintf("%d candidates with unique ids, bounded scores, and all five OS entries", len(candidates)))
	} else {
		add("candidate catalog", "fail", fmt.Sprintf("%d candidate integrity problem(s)", candidateProblems))
	}
	add("execution mode", "ok", "advisor-only; self-check executed no installers, project code, or elevation tools")

	failed := 0
	for _, c := range checks {
		if c.Status == "fail" {
			failed++
		}
	}
	code := exitOK
	if failed > 0 {
		code = exitInternal
	}
	if s.json {
		if err := s.encode(struct {
			Schema   string  `json:"schema"`
			Checks   []check `json:"checks"`
			Failed   int     `json:"failed"`
			ExitCode int     `json:"exit_code"`
		}{Schema: "deskweaver.self_check/v1", Checks: checks, Failed: failed, ExitCode: code}); err != nil {
			return exitInternal, err
		}
		return code, nil
	}
	s.printf("Deskweaver self-check\n")
	for _, c := range checks {
		s.printf("  [%s] %s: %s\n", c.Status, c.Name, safeText(c.Detail))
	}
	if failed == 0 {
		s.printf("\nSelf-check passed. It verifies the embedded rule and candidate catalogs, not your project.\n")
	} else {
		s.printf("\nSelf-check failed: %d check(s) need attention.\n", failed)
	}
	return code, nil
}

func flagBool(inv *invocation, name string) bool {
	v, _ := inv.bool(name)
	return v
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
