// Package doctor inspects the build host without changing it.
//
// Every probe is allowlisted and invoked directly with fixed arguments. The
// package never runs a shell, never executes project code, and never elevates
// privileges. Missing tools are reported with copy-pasteable guidance; nothing
// is installed automatically.
package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/luel-4013/deskweaver/internal/model"
)

// Options bounds host inspection.
type Options struct {
	Timeout time.Duration
	// Offline is accepted for call-site symmetry. Host probing is local and
	// never uses the network.
	Offline bool
	// HostOS overrides the reported build target. Probes still run on the
	// current host; a cross-target result is explicitly labeled as such.
	HostOS string
	// Distro overrides Linux distribution guidance, for example
	// "ubuntu-22.04". It never changes what is probed.
	Distro string
	// OptionalTools marks probed toolchains as informational instead of
	// required. MissingRequired ignores them.
	OptionalTools bool
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return 4 * time.Second
	}
	return o.Timeout
}

type probe struct {
	bins  []string
	args  []string
	label string
}

// probes is the complete allowlist. Anything not listed here is reported for
// manual verification rather than executed.
var probes = map[string]probe{
	"node":              {bins: []string{"node"}, args: []string{"--version"}},
	"npm":               {bins: []string{"npm"}, args: []string{"--version"}},
	"rustc":             {bins: []string{"rustc"}, args: []string{"--version"}},
	"cargo":             {bins: []string{"cargo"}, args: []string{"--version"}},
	"go":                {bins: []string{"go"}, args: []string{"version"}},
	"python3":           {bins: []string{"python3"}, args: []string{"--version"}},
	"pip":               {bins: []string{"pip3", "pip"}, args: []string{"--version"}},
	"php":               {bins: []string{"php"}, args: []string{"--version"}},
	"composer":          {bins: []string{"composer"}, args: []string{"--version"}},
	"ruby":              {bins: []string{"ruby"}, args: []string{"--version"}},
	"dotnet":            {bins: []string{"dotnet"}, args: []string{"--version"}},
	"java":              {bins: []string{"java"}, args: []string{"-version"}},
	"git":               {bins: []string{"git"}, args: []string{"--version"}},
	"pkg-config":        {bins: []string{"pkg-config"}, args: []string{"--version"}},
	"cmake":             {bins: []string{"cmake"}, args: []string{"--version"}},
	"compiler":          {bins: []string{"cc", "gcc", "clang"}, args: []string{"--version"}},
	"container-runtime": {bins: []string{"podman", "docker"}, args: []string{"--version"}},
	"systemd":           {bins: []string{"systemctl"}, args: []string{"--version"}},
	"polkit":            {bins: []string{"pkaction"}, args: []string{"--version"}},
	"qt":                {bins: []string{"qmake6", "qmake"}, args: []string{"--version"}},
	"android-sdk":       {label: "Android SDK"},
	"xcode":             {bins: []string{"xcodebuild"}, args: []string{"-version"}},
	"maui-workload":     {label: ".NET MAUI workload"},
	"webkit2gtk-4.1":    {label: "WebKitGTK 4.1"},
	"webkit2gtk-4.0":    {label: "WebKitGTK 4.0"},
}

// Check inspects the host and probes the requirements of the chosen
// recommendation. The result is deterministic except for discovered versions.
func Check(requirements []string, opts Options) model.Host {
	targetOS := runtime.GOOS
	if strings.TrimSpace(opts.HostOS) != "" {
		targetOS = normalizeHostOS(opts.HostOS)
	}
	host := model.Host{
		OS:   targetOS,
		Arch: runtime.GOARCH,
	}
	if targetOS == runtime.GOOS {
		host.Kernel = kernelVersion()
	}
	if targetOS == "linux" {
		release := readOSRelease()
		host.Distro = firstNonEmpty(release["PRETTY_NAME"], release["NAME"], release["ID"])
		host.Version = release["VERSION_ID"]
		host.Family = distroFamily(release)
		host.PackageManager = detectPackageManager(host.Family)
		if strings.TrimSpace(opts.Distro) != "" {
			host.Distro = strings.TrimSpace(opts.Distro)
			host.Version = versionFromDistro(host.Distro)
			if family := familyFromDistroName(host.Distro); family != "" {
				host.Family = family
			}
			host.PackageManager = expectedPackageManager(host.Family)
		}
	}
	if targetOS == runtime.GOOS {
		host.Session = detectSession()
	}

	for _, name := range dedupe(requirements) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		tool, check := probeRequirement(name, host, opts)
		host.Tools = append(host.Tools, tool)
		host.Checks = append(host.Checks, check)
	}

	host.Webviews = detectWebviews(targetOS, opts)
	for _, w := range host.Webviews {
		if !hasHostTool(host.Tools, w.Name) {
			host.Tools = append(host.Tools, w)
		}
	}
	host.Checks = append(host.Checks, hostChecks(host)...)
	host.Warnings = append(host.Warnings, hostWarnings(host, requirements)...)
	if targetOS != runtime.GOOS {
		host.Warnings = append(host.Warnings,
			fmt.Sprintf("Cross-target check: reporting %s, but probes ran on the current %s host. Verify versions and runtime libraries on the target OS.", targetOS, runtime.GOOS))
	}
	if len(host.Checks) > 0 {
		sort.SliceStable(host.Checks, func(i, j int) bool { return checkRank(host.Checks[i].Status) < checkRank(host.Checks[j].Status) })
	}
	return host
}

func normalizeHostOS(osName string) string {
	switch strings.ToLower(strings.TrimSpace(osName)) {
	case "linux":
		return "linux"
	case "windows", "win", "win32", "win64":
		return "windows"
	case "macos", "darwin", "osx", "mac":
		return "macos"
	default:
		return strings.ToLower(strings.TrimSpace(osName))
	}
}

func versionFromDistro(distro string) string {
	if i := strings.LastIndex(distro, "-"); i >= 0 && i+1 < len(distro) {
		candidate := distro[i+1:]
		if candidate != "" && candidate[0] >= '0' && candidate[0] <= '9' {
			return candidate
		}
	}
	return ""
}

func familyFromDistroName(distro string) string {
	name := strings.ToLower(distro)
	switch {
	case strings.Contains(name, "arch"), strings.Contains(name, "manjaro"), strings.Contains(name, "endeavouros"):
		return "arch"
	case strings.Contains(name, "ubuntu"), strings.Contains(name, "debian"), strings.Contains(name, "mint"),
		strings.Contains(name, "pop"), strings.Contains(name, "kali"), strings.Contains(name, "raspbian"):
		return "debian"
	case strings.Contains(name, "fedora"), strings.Contains(name, "rhel"), strings.Contains(name, "centos"),
		strings.Contains(name, "rocky"), strings.Contains(name, "alma"):
		return "fedora"
	case strings.Contains(name, "opensuse"), strings.Contains(name, "suse"), strings.Contains(name, "sles"):
		return "suse"
	case strings.Contains(name, "alpine"):
		return "alpine"
	default:
		return ""
	}
}

func expectedPackageManager(family string) string {
	switch family {
	case "arch":
		return "pacman"
	case "debian":
		return "apt-get"
	case "fedora":
		return "dnf"
	case "suse":
		return "zypper"
	case "alpine":
		return "apk"
	default:
		return ""
	}
}

func hasHostTool(tools []model.HostTool, name string) bool {
	for _, t := range tools {
		if strings.EqualFold(t.Name, name) {
			return true
		}
	}
	return false
}

// FilterRequirements removes toolchains that cannot matter for the requested
// targets. It prevents a Windows-only plan from being told that Linux
// WebKitGTK is a missing requirement.
func FilterRequirements(reqs []string, targets []string) []string {
	if len(targets) == 0 {
		return reqs
	}
	has := func(want string) bool {
		for _, t := range targets {
			if strings.EqualFold(strings.TrimSpace(t), want) {
				return true
			}
		}
		return false
	}
	linux := has("linux")
	macos := has("macos")
	android := has("android")
	nonLinux := has("windows") || macos || android || has("ios")
	var out []string
	for _, req := range reqs {
		switch {
		case strings.HasPrefix(req, "webkit2gtk") && !linux:
			continue
		case req == "xcode" && !macos:
			continue
		case req == "android-sdk" && !android:
			continue
		case req == "maui-workload" && !nonLinux:
			continue
		case (req == "systemd" || req == "polkit") && !linux:
			continue
		}
		out = append(out, req)
	}
	return out
}

// MissingRequired returns the names of required tools that were not found.
func MissingRequired(host model.Host) []string {
	var missing []string
	for _, t := range host.Tools {
		if t.Required && !t.Found {
			missing = append(missing, t.Name)
		}
	}
	return missing
}

func probeRequirement(name string, host model.Host, opts Options) (model.HostTool, model.HostCheck) {
	tool := model.HostTool{Name: name, Required: !opts.OptionalTools}
	check := model.HostCheck{Name: name}
	install := installHint(host.Family, name)
	verify := verifyHint(name)

	switch name {
	case "webkit2gtk-4.1", "webkit2gtk-4.0":
		found, path, version := pkgConfig(name, opts)
		tool.Found, tool.Path, tool.Version = found, path, version
		if found {
			check.Status = "ok"
			check.Detail = "found " + version
		} else {
			check.Status = "missing"
			check.Detail = "pkg-config could not resolve " + name
		}
		check.Install, check.Verify = install, verify
		return tool, check
	case "android-sdk":
		loc := firstNonEmpty(os.Getenv("ANDROID_SDK_ROOT"), os.Getenv("ANDROID_HOME"))
		if loc != "" {
			if st, err := os.Stat(loc); err == nil && st.IsDir() {
				tool.Found, tool.Path = true, loc
				tool.Version = ""
			}
		}
		if !tool.Found {
			if p, err := exec.LookPath("adb"); err == nil {
				tool.Found, tool.Path, tool.Version = true, p, shortVersion(runProbe(opts, p, "version"))
			}
		}
		if tool.Found {
			check.Status = "ok"
			check.Detail = "Android SDK or adb found; platform/emulator coverage still needs manual verification"
		} else {
			check.Status = "missing"
			check.Detail = "neither ANDROID_SDK_ROOT/ANDROID_HOME nor adb was found"
		}
		check.Install, check.Verify = install, verify
		return tool, check
	case "maui-workload":
		if p, err := exec.LookPath("dotnet"); err == nil {
			tool.Found, tool.Path = true, p
			tool.Version = shortVersion(runProbe(opts, p, "--version"))
			check.Status = "warn"
			check.Detail = ".NET found; verify the MAUI workload with: dotnet workload list (not executed by Deskweaver)"
		} else {
			check.Status = "missing"
			check.Detail = ".NET SDK not found"
		}
		check.Install, check.Verify = install, verify
		return tool, check
	}

	p, ok := probes[name]
	if !ok {
		tool.Required = false
		check.Status = "warn"
		check.Detail = "no allowlisted probe for this requirement; verify manually"
		check.Verify = "manual verification required"
		return tool, check
	}
	for _, bin := range p.bins {
		path, err := exec.LookPath(bin)
		if err != nil {
			continue
		}
		tool.Found, tool.Path = true, path
		tool.Version = shortVersion(runProbe(opts, path, p.args...))
		break
	}
	if tool.Found {
		check.Status = "ok"
		check.Detail = "found " + filepath.Base(tool.Path)
		if tool.Version != "" {
			check.Detail += " (" + tool.Version + ")"
		}
	} else {
		check.Status = "missing"
		check.Detail = "not found in PATH"
	}
	check.Install, check.Verify = install, verify
	return tool, check
}

func runProbe(opts Options, bin string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout())
	defer cancel()
	// #nosec G204 -- bin comes from LookPath and args are fixed allowlist values.
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return string(out)
}

func pkgConfig(name string, opts Options) (bool, string, string) {
	p, err := exec.LookPath("pkg-config")
	if err != nil {
		return false, "", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout())
	defer cancel()
	// #nosec G204 -- fixed arguments, no shell.
	cmd := exec.CommandContext(ctx, p, "--modversion", name)
	out, err := cmd.Output()
	if err != nil {
		return false, p, ""
	}
	version := shortVersion(string(out))
	return true, p, version
}

func shortVersion(s string) string {
	line := strings.TrimSpace(s)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if len(line) > 160 {
		line = line[:160] + "..."
	}
	return line
}

func readOSRelease() map[string]string {
	out := make(map[string]string)
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			if unquoted, err := strconv.Unquote(v); err == nil {
				v = unquoted
			} else {
				v = strings.Trim(v, `"'`)
			}
			out[strings.TrimSpace(k)] = v
		}
		break
	}
	return out
}

func distroFamily(release map[string]string) string {
	id := strings.ToLower(release["ID"])
	like := " " + strings.ToLower(release["ID_LIKE"]) + " "
	switch {
	case id == "arch" || id == "archarm" || strings.Contains(like, " arch "):
		return "arch"
	case id == "debian" || id == "ubuntu" || id == "linuxmint" || id == "pop" || id == "kali" || id == "raspbian" || strings.Contains(like, " debian ") || strings.Contains(like, " ubuntu "):
		return "debian"
	case id == "fedora" || id == "rhel" || id == "centos" || id == "rocky" || id == "alma" || strings.Contains(like, " fedora ") || strings.Contains(like, " rhel "):
		return "fedora"
	case id == "opensuse" || id == "opensuse-leap" || id == "opensuse-tumbleweed" || id == "sles" || strings.Contains(like, " suse "):
		return "suse"
	case id == "alpine" || strings.Contains(like, " alpine "):
		return "alpine"
	}
	return ""
}

func detectPackageManager(family string) string {
	order := map[string][]string{
		"arch":   {"pacman"},
		"debian": {"apt-get", "apt"},
		"fedora": {"dnf", "yum"},
		"suse":   {"zypper"},
		"alpine": {"apk"},
	}
	if family != "" {
		for _, bin := range order[family] {
			if _, err := exec.LookPath(bin); err == nil {
				return bin
			}
		}
	}
	for _, bin := range []string{"pacman", "apt-get", "dnf", "zypper", "apk", "xbps-install", "emerge", "nix-env"} {
		if _, err := exec.LookPath(bin); err == nil {
			return bin
		}
	}
	return ""
}

func kernelVersion() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func detectSession() string {
	if t := strings.ToLower(strings.TrimSpace(os.Getenv("XDG_SESSION_TYPE"))); t != "" && t != "unspecified" {
		return t
	}
	switch {
	case os.Getenv("WAYLAND_DISPLAY") != "":
		return "wayland"
	case os.Getenv("DISPLAY") != "":
		return "x11"
	case runtime.GOOS == "windows":
		return "windows"
	case runtime.GOOS == "darwin":
		return "aqua"
	default:
		return "unknown"
	}
}

func detectWebviews(hostOS string, opts Options) []model.HostTool {
	var out []model.HostTool
	if hostOS != runtime.GOOS {
		name := "system WebView"
		switch hostOS {
		case "linux":
			name = "WebKitGTK"
		case "windows":
			name = "WebView2"
		case "macos":
			name = "WKWebView"
		}
		return []model.HostTool{{
			Name:   name,
			Found:  false,
			Detail: "Cross-target check: verify the WebView runtime on the target host.",
		}}
	}
	switch hostOS {
	case "linux":
		for _, name := range []string{"webkit2gtk-4.1", "webkit2gtk-4.0"} {
			found, p, version := pkgConfig(name, opts)
			if found {
				out = append(out, model.HostTool{Name: name, Found: true, Path: p, Version: version})
			}
		}
		if len(out) == 0 {
			out = append(out, model.HostTool{Name: "webkit2gtk", Found: false})
		}
	case "windows":
		out = append(out, model.HostTool{
			Name:   "WebView2",
			Found:  true,
			Detail: "WebView2 runtime is normally present on Windows 10/11; verify on a clean VM.",
		})
	case "darwin":
		out = append(out, model.HostTool{Name: "WKWebView", Found: true, Detail: "System-provided; verify the minimum macOS version."})
	}
	return out
}

func hostChecks(host model.Host) []model.HostCheck {
	checks := []model.HostCheck{
		{Name: "operating system", Status: "ok", Detail: host.OS + "/" + host.Arch},
	}
	if host.Distro != "" {
		detail := host.Distro
		if host.Version != "" {
			detail += " " + host.Version
		}
		checks = append(checks, model.HostCheck{Name: "distribution", Status: "ok", Detail: detail})
	}
	if host.PackageManager != "" {
		checks = append(checks, model.HostCheck{Name: "package manager", Status: "ok", Detail: host.PackageManager})
	} else if host.OS == "linux" {
		checks = append(checks, model.HostCheck{Name: "package manager", Status: "warn", Detail: "not recognized; install guidance must be prepared manually"})
	}
	checks = append(checks, model.HostCheck{Name: "session", Status: "info", Detail: host.Session})
	return checks
}

func hostWarnings(host model.Host, requirements []string) []string {
	var warnings []string
	if host.OS != "linux" && host.OS != "windows" {
		warnings = append(warnings, "Deskweaver v0.1 targets Linux first and Windows second; this host is not a Tier 1 packaging target.")
	}
	if host.OS == "linux" && host.Session == "wayland" {
		warnings = append(warnings, "Wayland session: global shortcuts, tray icons, and screen capture often need portals or XWayland. Validate those features early.")
	}
	if host.OS == "linux" && (host.Session == "unknown" || host.Session == "tty") {
		warnings = append(warnings, "No graphical session detected; WebView launch and UI smoke tests need a display.")
	}
	if isContainer() {
		warnings = append(warnings, "Container environment detected; desktop launch, WebView, and GPU checks are unreliable here.")
	}
	if os.Geteuid() == 0 {
		warnings = append(warnings, "Deskweaver is running as root. Do not scan or build as root; use an unprivileged account.")
	}
	missing := 0
	for _, req := range dedupe(requirements) {
		found := false
		for _, t := range host.Tools {
			if strings.EqualFold(t.Name, req) && t.Found {
				found = true
				break
			}
		}
		if !found {
			missing++
		}
	}
	if missing > 0 {
		warnings = append(warnings, fmt.Sprintf("%d required host dependency(ies) missing; the plan cannot be built until they are installed and verified.", missing))
	}
	return warnings
}

func isContainer() bool {
	if os.Getenv("container") != "" || os.Getenv("CONTAINER") != "" {
		return true
	}
	for _, path := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func installHint(family, name string) string {
	pkg := packageFor(family, name)
	if pkg == "" {
		return ""
	}
	switch family {
	case "arch":
		return "pacman -S --needed " + pkg + "  (run with your normal elevation method; Deskweaver never executes it)"
	case "debian":
		return "apt-get install " + pkg + "  (run with your normal elevation method; Deskweaver never executes it)"
	case "fedora":
		return "dnf install " + pkg + "  (run with your normal elevation method; Deskweaver never executes it)"
	case "suse":
		return "zypper install " + pkg + "  (run with your normal elevation method; Deskweaver never executes it)"
	case "alpine":
		return "apk add " + pkg + "  (run as root; Deskweaver never executes it)"
	default:
		switch runtime.GOOS {
		case "windows":
			return "winget install " + pkg + "  (review the package ID first)"
		case "darwin":
			return "brew install " + pkg + "  (review the formula first)"
		}
	}
	return ""
}

func verifyHint(name string) string {
	switch name {
	case "webkit2gtk-4.1", "webkit2gtk-4.0":
		return "pkg-config --modversion " + name
	case "android-sdk":
		return "adb version"
	case "maui-workload":
		return "dotnet workload list"
	case "container-runtime":
		return "podman --version || docker --version"
	case "compiler":
		return "cc --version"
	case "qt":
		return "qmake6 --version || qmake --version"
	case "xcode":
		return "xcodebuild -version"
	case "java":
		return "java -version"
	default:
		if p, ok := probes[name]; ok && len(p.args) > 0 {
			return name + " " + strings.Join(p.args, " ")
		}
	}
	return "manual verification required"
}

func packageFor(family, name string) string {
	table := map[string]map[string]string{
		"node":              {"arch": "nodejs", "debian": "nodejs", "fedora": "nodejs", "suse": "nodejs", "alpine": "nodejs", "windows": "OpenJS.NodeJS.LTS", "darwin": "node"},
		"npm":               {"arch": "npm", "debian": "npm", "fedora": "npm", "suse": "npm", "alpine": "npm", "windows": "OpenJS.NodeJS.LTS", "darwin": "node"},
		"rustc":             {"arch": "rust", "debian": "rustc", "fedora": "rust", "suse": "rust", "alpine": "rust", "windows": "Rustlang.Rustup", "darwin": "rust"},
		"cargo":             {"arch": "rust", "debian": "cargo", "fedora": "cargo", "suse": "cargo", "alpine": "cargo", "windows": "Rustlang.Rustup", "darwin": "rust"},
		"go":                {"arch": "go", "debian": "golang-go", "fedora": "golang", "suse": "go", "alpine": "go", "windows": "GoLang.Go", "darwin": "go"},
		"python3":           {"arch": "python", "debian": "python3", "fedora": "python3", "suse": "python3", "alpine": "python3", "windows": "Python.Python.3.12", "darwin": "python@3.12"},
		"pip":               {"arch": "python-pip", "debian": "python3-pip", "fedora": "python3-pip", "suse": "python3-pip", "alpine": "py3-pip", "windows": "Python.Python.3.12", "darwin": "python@3.12"},
		"php":               {"arch": "php", "debian": "php", "fedora": "php", "suse": "php8", "alpine": "php83", "windows": "PHP.PHP", "darwin": "php"},
		"composer":          {"arch": "composer", "debian": "composer", "fedora": "composer", "suse": "composer", "alpine": "composer", "windows": "Composer.Composer", "darwin": "composer"},
		"ruby":              {"arch": "ruby", "debian": "ruby", "fedora": "ruby", "suse": "ruby", "alpine": "ruby", "windows": "RubyInstallerTeam.Ruby", "darwin": "ruby"},
		"dotnet":            {"arch": "dotnet-sdk", "debian": "dotnet-sdk-8.0", "fedora": "dotnet-sdk-8.0", "suse": "dotnet-sdk-8.0", "alpine": "dotnet8-sdk", "windows": "Microsoft.DotNet.SDK.8", "darwin": "dotnet"},
		"java":              {"arch": "jdk-openjdk", "debian": "default-jdk", "fedora": "java-17-openjdk-devel", "suse": "java-17-openjdk-devel", "alpine": "openjdk17", "windows": "EclipseAdoptium.Temurin.21.JDK", "darwin": "openjdk"},
		"git":               {"arch": "git", "debian": "git", "fedora": "git", "suse": "git", "alpine": "git", "windows": "Git.Git", "darwin": "git"},
		"pkg-config":        {"arch": "pkgconf", "debian": "pkg-config", "fedora": "pkgconf", "suse": "pkg-config", "alpine": "pkgconf", "windows": "msgpack.pkgconf", "darwin": "pkg-config"},
		"cmake":             {"arch": "cmake", "debian": "cmake", "fedora": "cmake", "suse": "cmake", "alpine": "cmake", "windows": "Kitware.CMake", "darwin": "cmake"},
		"compiler":          {"arch": "gcc", "debian": "build-essential", "fedora": "gcc", "suse": "gcc", "alpine": "build-base", "windows": "Microsoft.VisualStudio.2022.BuildTools", "darwin": "xcode"},
		"container-runtime": {"arch": "podman", "debian": "podman", "fedora": "podman", "suse": "podman", "alpine": "podman", "windows": "RedHat.Podman", "darwin": "podman"},
		"systemd":           {"arch": "systemd", "debian": "systemd", "fedora": "systemd", "suse": "systemd", "alpine": ""},
		"polkit":            {"arch": "polkit", "debian": "polkitd", "fedora": "polkit", "suse": "polkit", "alpine": "polkit"},
		"qt":                {"arch": "qt6-base", "debian": "qt6-base-dev", "fedora": "qt6-qtbase-devel", "suse": "qt6-base-devel", "alpine": "qt6-qtbase-dev"},
		"android-sdk":       {"arch": "android-tools", "debian": "adb", "fedora": "android-tools", "suse": "android-tools", "alpine": "android-tools"},
		"webkit2gtk-4.1":    {"arch": "webkit2gtk-4.1", "debian": "libwebkit2gtk-4.1-dev", "fedora": "webkit2gtk4.1-devel", "suse": "libwebkit2gtk4.1-devel", "alpine": "webkit2gtk-4.1-dev"},
		"webkit2gtk-4.0":    {"arch": "webkit2gtk", "debian": "libwebkit2gtk-4.0-dev", "fedora": "webkit2gtk4.0-devel", "suse": "libwebkit2gtk-4.0-devel", "alpine": "webkit2gtk-4.0-dev"},
	}
	if byFamily, ok := table[name]; ok {
		if family != "" {
			if pkg := byFamily[family]; pkg != "" {
				return pkg
			}
		}
		return byFamily[runtime.GOOS]
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func dedupe(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[strings.ToLower(v)] {
			continue
		}
		seen[strings.ToLower(v)] = true
		out = append(out, v)
	}
	return out
}

func checkRank(status string) int {
	switch status {
	case "missing":
		return 0
	case "warn":
		return 1
	case "info":
		return 2
	case "ok":
		return 3
	default:
		return 4
	}
}
