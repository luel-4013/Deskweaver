// Package rules loads and evaluates the declarative framework catalog.
//
// Rules are data, not code. They are embedded in the binary so the default
// scan works offline, and every match carries evidence that can be reviewed.
package rules

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/luel-4013/deskweaver/internal/model"
)

//go:embed catalog.json
var catalogFS embed.FS

// Catalog is the on-disk rule pack.
type Catalog struct {
	Schema    string `json:"schema"`
	Version   string `json:"version"`
	Updated   string `json:"updated"`
	Signature string `json:"signature"`
	Rules     []Rule `json:"rules"`
}

// Rule describes one framework or stack hypothesis.
type Rule struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Tier          string   `json:"tier"`
	Language      string   `json:"language"`
	DefaultTarget string   `json:"default_target"`
	Priority      int      `json:"priority"`
	Supersedes    []string `json:"supersedes,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	Notes         string   `json:"notes,omitempty"`
	Signals       []Signal `json:"signals"`
}

// Signal is one detection check.
type Signal struct {
	Kind     string `json:"kind"` // file_exists, dir_exists, manifest_dep, file_contains
	Manifest string `json:"manifest,omitempty"`
	Path     string `json:"path,omitempty"`
	Name     string `json:"name,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	Weight   int    `json:"weight"`
}

// Match is one evaluated rule.
type Match struct {
	Rule     Rule
	Score    int
	Evidence []model.Evidence
}

// Facts is the read-only fact base built by the scanner.
type Facts struct {
	Files    []string
	Dirs     map[string]bool
	Deps     map[string]map[string]bool
	Versions map[string]map[string]string
	Texts    map[string]string
}

// NewFacts returns an empty fact base.
func NewFacts() *Facts {
	return &Facts{
		Dirs:     make(map[string]bool),
		Deps:     make(map[string]map[string]bool),
		Versions: make(map[string]map[string]string),
		Texts:    make(map[string]string),
	}
}

// AddFile records a file and, optionally, its text.
func (f *Facts) AddFile(rel, text string) {
	rel = strings.TrimPrefix(strings.ReplaceAll(rel, "\\", "/"), "./")
	f.Files = append(f.Files, rel)
	if text != "" {
		f.Texts[rel] = text
	}
}

// SetText records text for a file that was already added.
func (f *Facts) SetText(rel, text string) {
	rel = strings.TrimPrefix(strings.ReplaceAll(rel, "\\", "/"), "./")
	if text != "" {
		f.Texts[rel] = text
	}
}

// AddDir records a directory.
func (f *Facts) AddDir(rel string) {
	rel = strings.Trim(strings.ReplaceAll(rel, "\\", "/"), "/")
	if rel != "" {
		f.Dirs[rel] = true
	}
}

// AddDep records a dependency from a manifest.
func (f *Facts) AddDep(manifest, name string) {
	f.AddDepVersion(manifest, name, "")
}

// AddDepVersion records a dependency and its declared version.
func (f *Facts) AddDepVersion(manifest, name, version string) {
	manifest = strings.ToLower(manifest)
	name = strings.ToLower(strings.TrimSpace(name))
	if manifest == "" || name == "" {
		return
	}
	if f.Deps[manifest] == nil {
		f.Deps[manifest] = make(map[string]bool)
	}
	f.Deps[manifest][name] = true
	if version != "" {
		if f.Versions[manifest] == nil {
			f.Versions[manifest] = make(map[string]string)
		}
		f.Versions[manifest][name] = strings.TrimSpace(version)
	}
}

// VersionOf returns the declared version of a dependency, if known.
func (f *Facts) VersionOf(manifest, name string) string {
	if f.Versions[strings.ToLower(manifest)] == nil {
		return ""
	}
	return f.Versions[strings.ToLower(manifest)][strings.ToLower(name)]
}

// Load reads and validates the embedded catalog.
func Load() (*Catalog, error) {
	b, err := catalogFS.ReadFile("catalog.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded catalog: %w", err)
	}
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks schema and signal syntax.
func (c *Catalog) Validate() error {
	if c.Schema != "deskweaver.rules/v1" {
		return fmt.Errorf("unsupported rule schema %q", c.Schema)
	}
	if len(c.Rules) == 0 {
		return fmt.Errorf("rule catalog is empty")
	}
	seen := make(map[string]bool, len(c.Rules))
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.ID == "" || r.Name == "" {
			return fmt.Errorf("rule %d: id and name are required", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		switch r.Tier {
		case string(model.TierA), string(model.TierB), string(model.TierC):
		default:
			return fmt.Errorf("rule %q: invalid tier %q", r.ID, r.Tier)
		}
		if len(r.Signals) == 0 {
			return fmt.Errorf("rule %q: no signals", r.ID)
		}
		for _, s := range r.Signals {
			switch s.Kind {
			case "file_exists", "dir_exists", "manifest_dep":
				if s.Path == "" && s.Manifest == "" {
					return fmt.Errorf("rule %q: signal %q needs a path or manifest", r.ID, s.Kind)
				}
			case "file_contains":
				if s.Path == "" || s.Pattern == "" {
					return fmt.Errorf("rule %q: file_contains needs path and pattern", r.ID)
				}
				if _, err := regexp.Compile(s.Pattern); err != nil {
					return fmt.Errorf("rule %q: invalid regex %q: %w", r.ID, s.Pattern, err)
				}
			default:
				return fmt.Errorf("rule %q: unknown signal kind %q", r.ID, s.Kind)
			}
			if s.Weight <= 0 {
				return fmt.Errorf("rule %q: signal weight must be positive", r.ID)
			}
		}
	}
	return nil
}

// Hash returns the SHA-256 of the catalog's canonical JSON.
func (c *Catalog) Hash() string {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Stats returns tier counts.
func (c *Catalog) Stats() map[string]int {
	out := map[string]int{"A": 0, "B": 0, "C": 0, "total": len(c.Rules)}
	for _, r := range c.Rules {
		out[r.Tier]++
	}
	return out
}

// RuleByID returns a rule by its identifier.
func (c *Catalog) RuleByID(id string) (Rule, bool) {
	for _, r := range c.Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// Evaluate returns all matching rules, sorted and with superseded rules
// removed. Higher-priority rules suppress generic parents (for example,
// Next.js suppresses React and Static HTML).
func (c *Catalog) Evaluate(f *Facts) []Match {
	if f == nil {
		return nil
	}
	var matches []Match
	for _, r := range c.Rules {
		m, ok := evaluateRule(r, f)
		if ok {
			matches = append(matches, m)
		}
	}

	// Remove rules superseded by a more specific match.
	suppressed := make(map[string]bool)
	for _, m := range matches {
		for _, id := range m.Rule.Supersedes {
			for _, other := range matches {
				if other.Rule.ID == id && other.Rule.ID != m.Rule.ID && m.Rule.Priority >= other.Rule.Priority {
					suppressed[id] = true
				}
			}
		}
	}
	filtered := matches[:0]
	for _, m := range matches {
		if !suppressed[m.Rule.ID] {
			filtered = append(filtered, m)
		}
	}
	matches = filtered

	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Score != matches[j].Score {
			return matches[i].Score > matches[j].Score
		}
		if tierRank(matches[i].Rule.Tier) != tierRank(matches[j].Rule.Tier) {
			return tierRank(matches[i].Rule.Tier) > tierRank(matches[j].Rule.Tier)
		}
		return matches[i].Rule.Priority > matches[j].Rule.Priority
	})
	return matches
}

func evaluateRule(r Rule, f *Facts) (Match, bool) {
	m := Match{Rule: r}
	seenEvidence := make(map[string]bool)
	strong := false
	for _, s := range r.Signals {
		ok, ev := matchSignal(s, f)
		if !ok {
			continue
		}
		// Shared toolchain files (for example vite.config.*) are weak on
		// their own. A rule needs at least one discriminating signal, not just
		// a coincidence, or every Vite app would also look like Vue and Solid.
		if s.Weight >= 25 {
			strong = true
		}
		m.Score += s.Weight
		key := ev.Kind + "|" + ev.Path + "|" + ev.Detail
		if !seenEvidence[key] {
			seenEvidence[key] = true
			m.Evidence = append(m.Evidence, ev)
		}
	}
	if m.Score == 0 || !strong {
		return Match{}, false
	}
	if m.Score > 100 {
		m.Score = 100
	}
	return m, true
}

func matchSignal(s Signal, f *Facts) (bool, model.Evidence) {
	switch s.Kind {
	case "file_exists":
		for _, file := range f.Files {
			if matchPath(s.Path, file) {
				return true, model.Evidence{Kind: s.Kind, Path: file, Detail: "file exists", Weight: s.Weight}
			}
		}
	case "dir_exists":
		want := strings.Trim(s.Path, "/")
		if f.Dirs[want] {
			return true, model.Evidence{Kind: s.Kind, Path: want, Detail: "directory exists", Weight: s.Weight}
		}
	case "manifest_dep":
		deps := f.Deps[strings.ToLower(s.Manifest)]
		if deps != nil && deps[strings.ToLower(s.Name)] {
			return true, model.Evidence{
				Kind:   s.Kind,
				Path:   s.Manifest,
				Detail: "dependency: " + s.Name,
				Weight: s.Weight,
			}
		}
	case "file_contains":
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return false, model.Evidence{}
		}
		for _, file := range f.Files {
			if !matchPath(s.Path, file) {
				continue
			}
			text, ok := f.Texts[file]
			if !ok {
				continue
			}
			if loc := re.FindStringIndex(text); loc != nil {
				line := lineAt(text, loc[0])
				return true, model.Evidence{
					Kind:   s.Kind,
					Path:   file,
					Detail: fmt.Sprintf("matched %q on line %d", truncate(line, 120), lineNumber(text, loc[0])),
					Weight: s.Weight,
				}
			}
		}
	}
	return false, model.Evidence{}
}

func matchPath(pattern, file string) bool {
	if pattern == "" {
		return false
	}
	file = strings.TrimPrefix(file, "./")
	if pattern == file {
		return true
	}
	if ok, _ := path.Match(pattern, file); ok {
		return true
	}
	if ok, _ := path.Match(pattern, path.Base(file)); ok {
		return true
	}
	return false
}

func lineAt(text string, offset int) string {
	if offset > len(text) {
		offset = len(text)
	}
	start := strings.LastIndexByte(text[:offset], '\n') + 1
	end := strings.IndexByte(text[offset:], '\n')
	if end < 0 {
		end = len(text)
	} else {
		end += offset
	}
	return strings.TrimSpace(text[start:end])
}

func lineNumber(text string, offset int) int {
	if offset > len(text) {
		offset = len(text)
	}
	return strings.Count(text[:offset], "\n") + 1
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func tierRank(t string) int {
	switch model.Tier(t) {
	case model.TierA:
		return 3
	case model.TierB:
		return 2
	case model.TierC:
		return 1
	default:
		return 0
	}
}

// SelfTest builds a minimal fact base for every rule and verifies that the
// rule can fire. It returns one error per rule that cannot be exercised.
func (c *Catalog) SelfTest() []error {
	var errs []error
	for _, r := range c.Rules {
		f := NewFacts()
		for _, s := range r.Signals {
			seedSignal(s, f)
		}
		matches := c.Evaluate(f)
		found := false
		for _, m := range matches {
			if m.Rule.ID == r.ID {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("rule %q did not fire on its own seed facts", r.ID))
		}
	}
	return errs
}

func seedSignal(s Signal, f *Facts) {
	switch s.Kind {
	case "file_exists":
		seed := seedPath(s.Path)
		f.AddFile(seed, "")
	case "dir_exists":
		f.AddDir(s.Path)
	case "manifest_dep":
		f.AddDep(s.Manifest, s.Name)
	case "file_contains":
		seed := seedPath(s.Path)
		f.AddFile(seed, sampleForPattern(s.Pattern))
	}
}

func seedPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.ReplaceAll(p, "*", "sample")
	p = strings.TrimPrefix(p, "./")
	if p == "" || strings.HasSuffix(p, "/") {
		return "sample.txt"
	}
	return p
}

func sampleForPattern(p string) string {
	samples := map[string]string{
		"^module ":                 "module example.com/sample\n",
		"spring-boot-starter-web":  "<dependency><artifactId>spring-boot-starter-web</artifactId></dependency>\n",
		"org.springframework.boot": "plugins { id 'org.springframework.boot' version '3.0.0' }\n",
		"quarkus":                  "<dependency><artifactId>quarkus-core</artifactId></dependency>\n",
		"micronaut":                "<dependency><artifactId>micronaut-core</artifactId></dependency>\n",
		"vaadin":                   "<dependency><artifactId>vaadin</artifactId></dependency>\n",
		"servlet":                  "<servlet><servlet-name>x</servlet-name></servlet>\n",
		"Router::new":              "let app = Router::new();\n",
		"HttpServer":               "HttpServer::new(|| App::new()).bind(addr)?;\n",
		"hx-[a-z]+=":               "<div hx-get=\"/x\"></div>\n",
		"x-data=":                  "<div x-data=\"{ open: false }\"></div>\n",
		"<%@":                      "<%@ page language=\"java\" %>\n",
	}
	if v, ok := samples[p]; ok {
		return v
	}
	// A literal pattern is often valid sample text; regex metacharacters are
	// harmless here because we only need one match.
	return p + "\n"
}
