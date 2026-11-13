// Package scan builds a read-only profile of a web project.
//
// It never executes project code, never follows symlinks, and never writes to
// the scanned tree. File reads are bounded by count, size, and total text.
package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/luel-4013/deskweaver/internal/model"
	"github.com/luel-4013/deskweaver/internal/rules"
)

// Options bounds a scan.
type Options struct {
	MaxFiles     int
	MaxFileSize  int64
	MaxTextBytes int64
	Workspace    string
}

// DefaultOptions returns conservative scan limits.
func DefaultOptions() Options {
	return Options{
		MaxFiles:     20000,
		MaxFileSize:  2 << 20,
		MaxTextBytes: 16 << 20,
	}
}

var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "vendor": true, "dist": true, "build": true,
	"target": true, "out": true, ".next": true, ".nuxt": true,
	".svelte-kit": true, ".astro": true, ".vercel": true, ".netlify": true,
	".venv": true, "venv": true, "__pycache__": true, ".pytest_cache": true,
	".mypy_cache": true, ".ruff_cache": true, ".tox": true,
	".cache": true, "coverage": true, ".nyc_output": true,
	".idea": true, ".gradle": true, ".mvn": true, "bin": true, "obj": true,
	"Pods": true, "DerivedData": true, ".dart_tool": true,
}

var textExtensions = map[string]bool{
	".json": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".vue": true, ".svelte": true, ".astro": true, ".html": true,
	".htm": true, ".css": true, ".scss": true, ".md": true, ".txt": true,
	".py": true, ".toml": true, ".cfg": true, ".ini": true, ".yaml": true,
	".yml": true, ".xml": true, ".cs": true, ".csproj": true, ".fs": true,
	".fsproj": true, ".java": true, ".kt": true, ".kts": true, ".gradle": true,
	".rs": true, ".go": true, ".mod": true, ".sum": true, ".php": true,
	".rb": true, ".gemspec": true, ".erb": true, ".sh": true, ".ps1": true,
	".sql": true, ".env": true, ".conf": true, ".properties": true,
	".webmanifest": true, ".svg": true, ".jsp": true, ".lock": true,
}

var (
	reRequirement  = regexp.MustCompile(`^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(?:[<>=~!]=?\s*([^;\s]+))?`)
	reGem          = regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)
	reCSProjPkg    = regexp.MustCompile(`<PackageReference\s+[^>]*Include="([^"]+)"(?:[^>]*Version="([^"]+)")?`)
	rePyQuoted     = regexp.MustCompile(`["']([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(?:[<>=~!][^"']*)?["']`)
	rePyKey        = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*=\s*["']([^"']+)["']`)
	reNextExport   = regexp.MustCompile(`(?m)output\s*:\s*['"]export['"]`)
	reNuxtSSRFalse = regexp.MustCompile(`(?m)ssr\s*:\s*false`)
	reAstroServer  = regexp.MustCompile(`(?m)(output\s*:\s*['"]server['"]|adapter\s*:)`)
)

// Scan profiles a project directory.
func Scan(root string, opts Options) (*model.Project, *rules.Facts, error) {
	if opts.MaxFiles <= 0 {
		opts = DefaultOptions()
	}
	origRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve project path: %w", err)
	}
	info, err := os.Stat(origRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("project path: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("project path is not a directory: %s", origRoot)
	}

	scanRoot := origRoot
	if opts.Workspace != "" {
		scanRoot, err = safeJoin(origRoot, opts.Workspace)
		if err != nil {
			return nil, nil, err
		}
		wi, err := os.Stat(scanRoot)
		if err != nil || !wi.IsDir() {
			return nil, nil, fmt.Errorf("workspace %q is not a readable directory", opts.Workspace)
		}
	}

	facts := rules.NewFacts()
	proj := &model.Project{
		Schema: "deskweaver.project/v1",
		Root:   scanRoot,
	}
	var warnings []string
	var textBytes int64
	var skipped int
	var files int

	err = filepath.WalkDir(scanRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			skipped++
			warnings = append(warnings, "unreadable path skipped: "+clean(filepath.ToSlash(p)))
			return nil
		}
		if p == scanRoot {
			return nil
		}
		rel, err := filepath.Rel(scanRoot, p)
		if err != nil {
			skipped++
			return nil
		}
		rel = filepath.ToSlash(rel)
		rel = clean(rel)
		if d.IsDir() {
			if skipDirs[d.Name()] {
				skipped++
				return fs.SkipDir
			}
			facts.AddDir(rel)
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			skipped++
			warnings = append(warnings, "symlink skipped (not followed): "+clean(rel))
			return nil
		}
		if !d.Type().IsRegular() {
			skipped++
			return nil
		}
		if files >= opts.MaxFiles {
			proj.Truncated = true
			return fs.SkipAll
		}
		files++
		fi, err := d.Info()
		if err != nil {
			skipped++
			return nil
		}
		if fi.Size() > opts.MaxFileSize {
			skipped++
			warnings = append(warnings, fmt.Sprintf("large file skipped (%d bytes): %s", fi.Size(), clean(rel)))
			facts.AddFile(rel, "")
			return nil
		}
		var text string
		if textBytes < opts.MaxTextBytes && likelyText(rel) {
			b, err := readBounded(p, opts.MaxFileSize)
			if err == nil && !bytes.Contains(b[:min(len(b), 8192)], []byte{0}) {
				text = sanitizeText(string(b))
				textBytes += int64(len(text))
			}
		}
		facts.AddFile(rel, text)
		return nil
	})
	if err != nil && !errors.Is(err, fs.SkipAll) {
		return nil, nil, fmt.Errorf("scan: %w", err)
	}
	proj.ScannedFiles = files
	proj.SkippedFiles = skipped

	// Parse manifests and collect dependencies.
	meta := parseManifests(facts)
	proj.Name = meta.name
	if proj.Name == "" {
		proj.Name = filepath.Base(scanRoot)
	}
	proj.Name = clean(proj.Name)
	proj.Monorepo = meta.monorepo
	proj.Workspaces = meta.workspaces

	catalog, err := rules.Load()
	if err != nil {
		return nil, nil, err
	}
	matches := catalog.Evaluate(facts)
	for _, m := range matches {
		d := detectionFromMatch(m, facts)
		proj.Detections = append(proj.Detections, d)
	}
	if len(proj.Detections) > 0 {
		primary := proj.Detections[0]
		proj.Primary = &primary
		proj.Capabilities = append([]string(nil), primary.Capabilities...)
	} else {
		proj.Capabilities = []string{"unknown"}
		proj.Unknowns = append(proj.Unknowns, "No known framework matched; a manual profile is required.")
	}

	if len(proj.Detections) > 3 {
		proj.Detections = proj.Detections[:3]
	}
	for _, d := range proj.Detections {
		if d.Tier == model.TierC {
			proj.Unknowns = append(proj.Unknowns, fmt.Sprintf("%s is Tier C: manual review required before recommending a target.", d.Name))
		}
		if d.Tier == model.TierB {
			proj.Unknowns = append(proj.Unknowns, fmt.Sprintf("%s is Tier B: the profile is standard, not deep; verify capabilities before building.", d.Name))
		}
	}
	if proj.Monorepo {
		if len(proj.Workspaces) > 0 {
			warnings = append(warnings, "monorepo/workspace detected; select a workspace before planning: "+strings.Join(proj.Workspaces, ", "))
		} else {
			warnings = append(warnings, "monorepo marker detected; select the app directory before planning.")
		}
	}
	if !hasAnyFile(facts, "LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md") {
		proj.Unknowns = append(proj.Unknowns, "License not detected.")
	}
	if hasAnyFile(facts, "package.json") && !hasAnyFile(facts, "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock") {
		warnings = append(warnings, "JavaScript lockfile not found; dependency versions may be ranges.")
	}
	if proj.Truncated {
		warnings = append(warnings, fmt.Sprintf("file limit reached (%d); detection may be incomplete.", opts.MaxFiles))
	}
	proj.Warnings = append(proj.Warnings, warnings...)
	proj.Unknowns = append(proj.Unknowns, "EOL status is not yet checked by this build; verify the framework version before release.")
	return proj, facts, nil
}

type manifestMeta struct {
	name       string
	monorepo   bool
	workspaces []string
}

func parseManifests(facts *rules.Facts) manifestMeta {
	var meta manifestMeta
	var packageDirs []string
	for _, rel := range facts.Files {
		text, ok := facts.Texts[rel]
		if !ok {
			continue
		}
		base := path.Base(rel)
		switch {
		case base == "package.json":
			name, workspaces, err := parsePackageJSON(rel, text, facts)
			if err == nil {
				dir := path.Dir(rel)
				if dir != "." {
					packageDirs = append(packageDirs, dir)
				}
				if meta.name == "" && (dir == "." || rel == "package.json") {
					meta.name = name
				}
				if workspaces {
					meta.monorepo = true
				}
			}
		case base == "requirements.txt" || (strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")):
			parseRequirements(text, facts)
		case base == "pyproject.toml":
			parsePyProject(text, facts, &meta)
		case base == "composer.json":
			parseComposer(text, facts, &meta)
		case base == "Gemfile":
			parseGemfile(text, facts)
		case base == "go.mod":
			parseGoMod(text, facts, &meta)
		case base == "Cargo.toml":
			parseCargo(text, facts)
		case strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".fsproj"):
			parseCSProj(text, facts)
		}
	}
	// Workspace markers.
	if hasAnyFile(facts, "pnpm-workspace.yaml", "lerna.json", "nx.json", "turbo.json", "go.work") {
		meta.monorepo = true
	}
	// Package directories under the root are workspace candidates.
	seen := make(map[string]bool)
	for _, dir := range packageDirs {
		if dir == "" || strings.HasPrefix(dir, ".") || seen[dir] {
			continue
		}
		seen[dir] = true
		meta.workspaces = append(meta.workspaces, dir)
	}
	sort.Strings(meta.workspaces)
	if len(meta.workspaces) > 20 {
		meta.workspaces = meta.workspaces[:20]
	}
	return meta
}

func parsePackageJSON(rel, text string, facts *rules.Facts) (string, bool, error) {
	var m struct {
		Name            string            `json:"name"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
		Workspaces      json.RawMessage   `json:"workspaces"`
	}
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return "", false, err
	}
	for name, version := range m.Dependencies {
		facts.AddDepVersion("package.json", name, version)
	}
	for name, version := range m.DevDependencies {
		facts.AddDepVersion("package.json", name, version)
	}
	hasWorkspaces := len(m.Workspaces) > 0 && string(m.Workspaces) != "null"
	return m.Name, hasWorkspaces, nil
}

func parseRequirements(text string, facts *rules.Facts) {
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		m := reRequirement.FindStringSubmatch(line)
		if len(m) >= 2 {
			facts.AddDepVersion("requirements.txt", m[1], versionAt(m, 2))
		}
	}
}

func parsePyProject(text string, facts *rules.Facts, meta *manifestMeta) {
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.Trim(trimmed, "[]"))
			continue
		}
		if strings.HasPrefix(section, "tool.poetry") && strings.Contains(section, "dependencies") {
			if m := rePyKey.FindStringSubmatch(trimmed); len(m) == 3 && strings.ToLower(m[1]) != "python" {
				facts.AddDepVersion("pyproject.toml", m[1], m[2])
			}
		}
		if section == "project" && (strings.HasPrefix(trimmed, "dependencies") || strings.HasPrefix(trimmed, "\"") || strings.HasPrefix(trimmed, "'")) {
			for _, m := range rePyQuoted.FindAllStringSubmatch(trimmed, -1) {
				facts.AddDep("pyproject.toml", m[1])
			}
		}
		if section == "project" && strings.HasPrefix(strings.ToLower(trimmed), "name") {
			if m := rePyKey.FindStringSubmatch(trimmed); len(m) == 3 {
				meta.name = m[2]
			}
		}
	}
}

func parseComposer(text string, facts *rules.Facts, meta *manifestMeta) {
	var m struct {
		Name    string            `json:"name"`
		Require map[string]string `json:"require"`
		Dev     map[string]string `json:"require-dev"`
	}
	if json.Unmarshal([]byte(text), &m) != nil {
		return
	}
	if meta.name == "" {
		meta.name = m.Name
	}
	for name, version := range m.Require {
		facts.AddDepVersion("composer.json", name, version)
	}
	for name, version := range m.Dev {
		facts.AddDepVersion("composer.json", name, version)
	}
}

func parseGemfile(text string, facts *rules.Facts) {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if m := reGem.FindStringSubmatch(line); len(m) >= 2 {
			facts.AddDepVersion("Gemfile", m[1], versionAt(m, 2))
		}
	}
}

func parseGoMod(text string, facts *rules.Facts, meta *manifestMeta) {
	inBlock := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == "module" && meta.name == "" {
			meta.name = path.Base(fields[1])
		}
		if strings.HasPrefix(trimmed, "require (") {
			inBlock = true
			continue
		}
		if inBlock && trimmed == ")" {
			inBlock = false
			continue
		}
		if strings.HasPrefix(trimmed, "require ") {
			fields = strings.Fields(strings.TrimPrefix(trimmed, "require "))
			if len(fields) >= 1 {
				facts.AddDepVersion("go.mod", fields[0], versionAt(fields, 1))
			}
			continue
		}
		if inBlock && len(fields) >= 1 && !strings.HasPrefix(trimmed, "//") {
			facts.AddDepVersion("go.mod", fields[0], versionAt(fields, 1))
		}
	}
}

func parseCargo(text string, facts *rules.Facts) {
	section := ""
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.Trim(trimmed, "[]"))
			continue
		}
		if section != "dependencies" && section != "dev-dependencies" && section != "build-dependencies" && section != "workspace.dependencies" {
			continue
		}
		key := ""
		version := ""
		if i := strings.IndexByte(trimmed, '='); i > 0 {
			key = strings.TrimSpace(trimmed[:i])
			version = strings.Trim(strings.TrimSpace(trimmed[i+1:]), `"'`)
		} else if strings.HasPrefix(trimmed, "[") {
			continue
		}
		if key != "" && !strings.HasPrefix(key, "#") {
			facts.AddDepVersion("Cargo.toml", key, version)
		}
	}
}

func parseCSProj(text string, facts *rules.Facts) {
	if strings.Contains(text, "Microsoft.NET.Sdk.Web") || strings.Contains(text, "Microsoft.AspNetCore") {
		facts.AddDepVersion("csproj", "Microsoft.AspNetCore", "")
	}
	if strings.Contains(text, "Microsoft.AspNetCore.Components.WebAssembly") {
		facts.AddDepVersion("csproj", "Microsoft.AspNetCore.Components.WebAssembly", "")
		facts.AddDepVersion("csproj", "Microsoft.AspNetCore.Components", "")
	}
	if strings.Contains(text, "Microsoft.AspNetCore.Components.Server") {
		facts.AddDepVersion("csproj", "Microsoft.AspNetCore.Components.Server", "")
		facts.AddDepVersion("csproj", "Microsoft.AspNetCore.Components", "")
	}
	for _, m := range reCSProjPkg.FindAllStringSubmatch(text, -1) {
		if len(m) >= 2 {
			facts.AddDepVersion("csproj", m[1], versionAt(m, 2))
		}
	}
}

func detectionFromMatch(m rules.Match, facts *rules.Facts) model.Detection {
	d := model.Detection{
		RuleID:        m.Rule.ID,
		Name:          m.Rule.Name,
		Tier:          model.Tier(m.Rule.Tier),
		Language:      m.Rule.Language,
		Confidence:    confidenceFor(m.Score),
		Score:         m.Score,
		Evidence:      cleanEvidence(m.Evidence),
		Capabilities:  append([]string(nil), m.Rule.Capabilities...),
		DefaultTarget: m.Rule.DefaultTarget,
		Notes:         m.Rule.Notes,
		ManualReview:  model.Tier(m.Rule.Tier) == model.TierC,
	}
	for _, ev := range d.Evidence {
		if strings.HasPrefix(ev.Detail, "dependency: ") {
			name := strings.TrimPrefix(ev.Detail, "dependency: ")
			if v := facts.VersionOf(ev.Path, name); v != "" {
				d.Version = clean(v)
				break
			}
		}
	}
	applyVariant(&d, facts)
	return d
}

func applyVariant(d *model.Detection, facts *rules.Facts) {
	switch d.RuleID {
	case "react":
		if hasDep(facts, "package.json", "vite") {
			d.Name = "React + Vite"
		} else if hasDep(facts, "package.json", "react-scripts") {
			d.Name = "React (CRA)"
		}
	case "vue":
		if hasDep(facts, "package.json", "nuxt") {
			d.Name = "Nuxt"
			d.Variant = "nuxt"
			if nuxtConfig := firstText(facts, "nuxt.config.*"); reNuxtSSRFalse.MatchString(nuxtConfig) {
				d.Capabilities = []string{"static", "node"}
			} else {
				d.Capabilities = []string{"server", "node"}
			}
		}
	case "svelte":
		if hasDep(facts, "package.json", "@sveltejs/kit") {
			d.Name = "SvelteKit"
			d.Variant = "sveltekit"
			if hasDep(facts, "package.json", "@sveltejs/adapter-static") {
				d.Capabilities = []string{"static"}
			} else {
				d.Capabilities = []string{"server", "node"}
			}
		}
	case "nextjs":
		d.Variant = "nextjs"
		if cfg := firstText(facts, "next.config.*"); reNextExport.MatchString(cfg) {
			d.Capabilities = []string{"static", "node"}
			d.Notes += " Static export detected; verify that no server-only features are used."
		}
	case "astro":
		if cfg := firstText(facts, "astro.config.*"); reAstroServer.MatchString(cfg) {
			d.Capabilities = []string{"server", "node"}
		}
	case "go-http":
		switch {
		case hasDep(facts, "go.mod", "github.com/gin-gonic/gin"):
			d.Name = "Gin"
		case hasDep(facts, "go.mod", "github.com/labstack/echo/v4"):
			d.Name = "Echo"
		case hasDep(facts, "go.mod", "github.com/gofiber/fiber/v2"):
			d.Name = "Fiber"
		case hasDep(facts, "go.mod", "github.com/go-chi/chi/v5"):
			d.Name = "Chi"
		case hasDep(facts, "go.mod", "github.com/gorilla/mux"):
			d.Name = "Gorilla Mux"
		}
	case "aspnet-blazor":
		switch {
		case hasDep(facts, "csproj", "Microsoft.AspNetCore.Components.WebAssembly"):
			d.Name = "Blazor WebAssembly"
			d.Variant = "blazor-wasm"
			d.Capabilities = []string{"static", "dotnet"}
		case hasDep(facts, "csproj", "Microsoft.AspNetCore.Components.Server"):
			d.Name = "Blazor Server"
			d.Variant = "blazor-server"
			d.Capabilities = []string{"server", "dotnet"}
		}
	case "static-web":
		if hasAnyFile(facts, "manifest.webmanifest", "sw.js", "service-worker.js") {
			d.Name = "Static HTML/PWA"
			d.Variant = "pwa"
		}
	case "ionic":
		d.Variant = "mobile"
	case "react-native", "expo":
		d.Variant = "mobile"
	case "jupyter":
		d.Variant = "do-not-package"
	case "vaadin", "jsp-servlet":
		d.Variant = "legacy"
	}
}

func confidenceFor(score int) model.Confidence {
	switch {
	case score >= 70:
		return model.ConfidenceHigh
	case score >= 40:
		return model.ConfidenceMedium
	default:
		return model.ConfidenceLow
	}
}

func cleanEvidence(in []model.Evidence) []model.Evidence {
	out := make([]model.Evidence, 0, len(in))
	for _, ev := range in {
		ev.Kind = clean(ev.Kind)
		ev.Path = clean(ev.Path)
		ev.Detail = clean(ev.Detail)
		out = append(out, ev)
	}
	return out
}

func hasDep(f *rules.Facts, manifest, name string) bool {
	deps := f.Deps[strings.ToLower(manifest)]
	return deps != nil && deps[strings.ToLower(name)]
}

func hasAnyFile(f *rules.Facts, names ...string) bool {
	for _, file := range f.Files {
		for _, name := range names {
			if path.Base(file) == name || file == name {
				return true
			}
		}
	}
	return false
}

func firstText(f *rules.Facts, pattern string) string {
	for _, file := range f.Files {
		if ok, _ := path.Match(pattern, file); ok {
			if text, ok := f.Texts[file]; ok {
				return text
			}
		}
		if ok, _ := path.Match(pattern, path.Base(file)); ok {
			if text, ok := f.Texts[file]; ok {
				return text
			}
		}
	}
	return ""
}

func safeJoin(root, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("workspace must be relative to the project root")
	}
	target := filepath.Join(root, rel)
	check, err := filepath.Rel(root, target)
	if err != nil || strings.HasPrefix(check, "..") || filepath.IsAbs(check) {
		return "", fmt.Errorf("workspace escapes the project root")
	}
	return target, nil
}

func likelyText(rel string) bool {
	ext := strings.ToLower(path.Ext(rel))
	if textExtensions[ext] {
		return true
	}
	base := strings.ToLower(path.Base(rel))
	return base == "gemfile" || base == "go.mod" || base == "go.sum" ||
		base == "dockerfile" || base == "makefile" || base == "procfile" ||
		strings.HasPrefix(base, ".env") || base == "artisan" || base == "yii"
}

func readBounded(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, limit)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

func versionAt(fields []string, i int) string {
	if i < len(fields) {
		return fields[i]
	}
	return ""
}

func sanitizeText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			return r
		case r >= 32 && r != unicode.ReplacementChar:
			return r
		default:
			return '?'
		}
	}, s)
}

func clean(s string) string {
	return strings.TrimSpace(sanitizeText(s))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	// Keep strconv linked for future version normalization; it also documents
	// that we intentionally avoid parsing versions as numbers.
	_ = strconv.IntSize
}
