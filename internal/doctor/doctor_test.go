package doctor

import (
	"strings"
	"testing"
	"time"
)

func TestCheckReportsGo(t *testing.T) {
	host := Check([]string{"go", "definitely-not-a-real-tool"}, Options{Timeout: 10 * time.Second})
	if host.OS == "" || host.Arch == "" {
		t.Fatalf("host is incomplete: %#v", host)
	}
	var goTool *bool
	for i := range host.Tools {
		if host.Tools[i].Name == "go" {
			goTool = &host.Tools[i].Found
		}
	}
	if goTool == nil {
		t.Fatal("go was not probed")
	}
	if !*goTool {
		t.Skip("go is not on PATH in this test environment")
	}
	var unknownWarned bool
	for _, c := range host.Checks {
		if c.Name == "definitely-not-a-real-tool" && c.Status == "warn" {
			unknownWarned = true
		}
	}
	if !unknownWarned {
		t.Fatal("unknown requirements must be reported for manual verification, not executed")
	}
}

func TestGuidanceHasNoPrivilegeOrPipeToShell(t *testing.T) {
	for _, family := range []string{"arch", "debian", "fedora", "suse", "alpine"} {
		for name := range probes {
			hint := installHint(family, name)
			lower := strings.ToLower(hint)
			if strings.Contains(lower, "sudo ") || strings.Contains(lower, "curl ") || strings.Contains(lower, "| sh") || strings.Contains(lower, "| bash") {
				t.Fatalf("unsafe guidance for %s/%s: %q", family, name, hint)
			}
		}
	}
}

func TestPackageForKnownFamilies(t *testing.T) {
	if got := packageFor("arch", "node"); got != "nodejs" {
		t.Fatalf("arch node package = %q", got)
	}
	if got := packageFor("debian", "pkg-config"); got != "pkg-config" {
		t.Fatalf("debian pkg-config package = %q", got)
	}
	if got := packageFor("fedora", "webkit2gtk-4.1"); got != "webkit2gtk4.1-devel" {
		t.Fatalf("fedora webkit package = %q", got)
	}
}

func TestDistroFamily(t *testing.T) {
	cases := []struct {
		release map[string]string
		want    string
	}{
		{map[string]string{"ID": "manjaro", "ID_LIKE": "arch"}, "arch"},
		{map[string]string{"ID": "ubuntu", "ID_LIKE": "debian"}, "debian"},
		{map[string]string{"ID": "fedora"}, "fedora"},
		{map[string]string{"ID": "opensuse-tumbleweed", "ID_LIKE": "suse"}, "suse"},
		{map[string]string{"ID": "alpine"}, "alpine"},
		{map[string]string{"ID": "unknown"}, ""},
	}
	for _, tc := range cases {
		if got := distroFamily(tc.release); got != tc.want {
			t.Errorf("distroFamily(%v) = %q, want %q", tc.release, got, tc.want)
		}
	}
}

func TestNoShellProbeAllowlist(t *testing.T) {
	for _, name := range []string{"sh", "bash", "zsh", "sudo", "curl", "wget", "rm", "dd"} {
		if _, ok := probes[name]; ok {
			t.Fatalf("dangerous command %q is allowlisted", name)
		}
	}
}
