package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
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

func TestReactVite(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json":   `{"name":"example-app","dependencies":{"react":"^19.0.0","react-dom":"^19.0.0"},"devDependencies":{"vite":"^8.0.0"}}`,
		"vite.config.ts": `export default {}`,
		"index.html":     `<div id="root"></div>`,
		"src/main.tsx":   `console.log("hi")`,
	})
	p, _, err := Scan(root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if p.Primary == nil || p.Primary.RuleID != "react" {
		t.Fatalf("primary = %#v, want react", p.Primary)
	}
	if p.Primary.Name != "React + Vite" {
		t.Fatalf("name = %q, want React + Vite", p.Primary.Name)
	}
	if !contains(p.Primary.Capabilities, "static") {
		t.Fatalf("capabilities = %v, want static", p.Primary.Capabilities)
	}
	if p.Name != "example-app" {
		t.Fatalf("project name = %q", p.Name)
	}
}

func TestNextServer(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json":   `{"dependencies":{"next":"^15.0.0","react":"^19.0.0"}}`,
		"next.config.js": `module.exports = {}`,
		"app/page.tsx":   `export default function Page(){return null}`,
	})
	p, _, err := Scan(root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if p.Primary == nil || p.Primary.RuleID != "nextjs" {
		t.Fatalf("primary = %#v, want nextjs", p.Primary)
	}
	if !contains(p.Primary.Capabilities, "server") {
		t.Fatalf("capabilities = %v, want server", p.Primary.Capabilities)
	}
	for _, d := range p.Detections {
		if d.RuleID == "react" {
			t.Fatal("react should be suppressed by nextjs")
		}
	}
}

func TestDjango(t *testing.T) {
	root := writeTree(t, map[string]string{
		"requirements.txt": "Django==4.2.11\n",
		"manage.py":        "#!/usr/bin/env python\n",
		"settings.py":      "DEBUG = False\n",
	})
	p, _, err := Scan(root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if p.Primary == nil || p.Primary.RuleID != "django" {
		t.Fatalf("primary = %#v, want django", p.Primary)
	}
	if p.Primary.Version != "4.2.11" {
		t.Fatalf("version = %q, want 4.2.11", p.Primary.Version)
	}
}

func TestLaravel(t *testing.T) {
	root := writeTree(t, map[string]string{
		"composer.json": `{"require":{"php":"^8.3","laravel/framework":"^11.0"}}`,
		"artisan":       "#!/usr/bin/env php\n",
	})
	p, _, err := Scan(root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if p.Primary == nil || p.Primary.RuleID != "laravel" {
		t.Fatalf("primary = %#v, want laravel", p.Primary)
	}
}

func TestGoGin(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":  "module example.com/demo\n\ngo 1.24\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.10.0\n)\n",
		"main.go": "package main\nfunc main(){}\n",
	})
	p, _, err := Scan(root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if p.Primary == nil || p.Primary.RuleID != "go-http" {
		t.Fatalf("primary = %#v, want go-http", p.Primary)
	}
	if p.Primary.Name != "Gin" {
		t.Fatalf("name = %q, want Gin", p.Primary.Name)
	}
}

func TestGoStdlibHTTP(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":               "module example.com/demo\n\ngo 1.27.1\n",
		"main.go":              "package main\n\nimport \"net/http\"\n\nfunc main() { http.ListenAndServe(\"127.0.0.1:8080\", nil) }\n",
		"index.html":           "<!doctype html><html><body>demo</body></html>\n",
		"templates/index.html": "<h1>demo</h1>\n",
	})
	p, _, err := Scan(root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if p.Primary == nil || p.Primary.RuleID != "go-http" {
		t.Fatalf("primary = %#v, want go-http for a stdlib net/http server", p.Primary)
	}
}

func TestSpringBoot(t *testing.T) {
	root := writeTree(t, map[string]string{
		"pom.xml":         `<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>`,
		"application.yml": "server:\n  port: 8080\n",
	})
	p, _, err := Scan(root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if p.Primary == nil || p.Primary.RuleID != "spring-boot" {
		t.Fatalf("primary = %#v, want spring-boot", p.Primary)
	}
}

func TestStaticPWA(t *testing.T) {
	root := writeTree(t, map[string]string{
		"index.html":           `<html></html>`,
		"manifest.webmanifest": `{"name":"Demo"}`,
		"sw.js":                `self.addEventListener("fetch", () => {})`,
	})
	p, _, err := Scan(root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if p.Primary == nil || p.Primary.RuleID != "static-web" {
		t.Fatalf("primary = %#v, want static-web", p.Primary)
	}
	if p.Primary.Variant != "pwa" {
		t.Fatalf("variant = %q, want pwa", p.Primary.Variant)
	}
}

func TestMonorepoDetected(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json":              `{"name":"root","workspaces":["packages/*"]}`,
		"packages/web/package.json": `{"name":"web","dependencies":{"next":"15.0.0"}}`,
	})
	p, _, err := Scan(root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !p.Monorepo {
		t.Fatal("expected monorepo")
	}
	if len(p.Workspaces) == 0 || p.Workspaces[0] != "packages/web" {
		t.Fatalf("workspaces = %v", p.Workspaces)
	}
}

func TestSymlinkNotFollowed(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOP SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := writeTree(t, map[string]string{"index.html": `<html></html>`})
	if err := os.Symlink(secret, filepath.Join(root, "linked.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, facts, err := Scan(root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range facts.Files {
		if f == "linked.txt" {
			t.Fatal("symlink was followed")
		}
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
