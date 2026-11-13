// Package security turns the threat model and chosen technology into an
// auditable set of controls and residual risks.
//
// This package is advisory: it produces text, never configuration changes.
package security

import (
	"fmt"
	"strings"

	"github.com/luel-4013/deskweaver/internal/model"
)

// Build returns the security plan for the detected project and recommendation.
func Build(p *model.Project, rec model.Recommendation, ans model.Answers) model.SecurityPlan {
	profile := normalizeProfile(ans.Profile)
	sensitivity := normalizeSensitivity(ans.Sensitivity)
	network := normalizeNetwork(ans.Network)
	privilege := normalizePrivilege(ans.Privilege)
	threat := model.ThreatModel{
		Sensitivity:    sensitivity,
		UntrustedInput: ans.UntrustedInput,
		Network:        network,
		Privilege:      privilege,
	}
	plan := model.SecurityPlan{
		Profile:     profile,
		ThreatModel: threat,
	}

	candidateID := "manual"
	if rec.Primary != nil {
		candidateID = rec.Primary.ID
	}
	caps := capabilities(p)
	webShell := isWebShell(candidateID)
	server := hasServer(caps) || candidateID == "nativephp" || candidateID == "container"
	desktopTarget := hasAny(ans.Targets, "linux", "windows", "macos")

	add := func(id, name, status, detail string) {
		plan.Controls = append(plan.Controls, model.Control{ID: id, Name: name, Status: status, Detail: detail})
	}

	if webShell {
		add("SEC-CSP-01", "Strict content security policy", "required",
			"Ship a strict CSP with no inline scripts, no eval, no remote fonts/CDNs, and no wildcard connect-src. Review the generated csp.txt before use.")
		add("SEC-NAV-01", "Deny navigation and new windows", "required",
			"Deny unexpected navigation, window.open, webview tags, and permission requests. Allowlist only local, bundled origins.")
	}
	switch candidateID {
	case "electron":
		add("SEC-SHELL-01", "Electron renderer isolation", "required",
			"sandbox: true, contextIsolation: true, nodeIntegration: false, webSecurity: true, allowRunningInsecureContent: false. Do not relax these to make a library work.")
	case "tauri", "wails":
		add("SEC-SHELL-02", "Minimal shell capabilities", "required",
			"Use a minimal capability set: no shell:default, no fs:default, no http:default, withGlobalTauri: false. Add permissions one at a time with a review note.")
	}
	if hasIPC(candidateID) {
		add("SEC-IPC-01", "Narrow IPC allowlist", "required",
			"Expose only named commands/messages; validate the sender and schema-validate every payload. Never forward arbitrary URLs, paths, or shell strings.")
	}
	if server {
		add("SEC-LOCAL-01", "Loopback-only local API", "required",
			"Bind to 127.0.0.1 (or ::1), choose a random port, require a per-launch token delivered over stdin/pipe, and check Host, Origin, and Sec-Fetch-Site. Add a CSRF token and request-size limits.")
		if profile == "airgap" || network == "offline" || privilege != "none" {
			add("SEC-LOCAL-02", "Prefer a Unix socket or named pipe", "required",
				"Use $XDG_RUNTIME_DIR with mode 0600 on Linux, or a Windows named pipe with an ACL. TCP is a fallback, not the default.")
		} else {
			add("SEC-LOCAL-02", "Prefer a Unix socket or named pipe", "recommended",
				"A local socket or named pipe avoids same-user port scanning and browser-origin confusion.")
		}
		add("SEC-SIDE-01", "Sidecar integrity", "required",
			"Launch sidecars by absolute path with fixed arguments and no shell. Verify a hash or signature before launch and run with the least privilege that works.")
		add("SEC-SIDE-02", "Sidecar lifecycle", "required",
			"Kill the entire process tree on exit (process group on Unix, Job Object on Windows), health-check it, and restart with a bounded policy.")
	}
	if sensitivity == "confidential" || sensitivity == "regulated" || profile == "hardened" || profile == "airgap" {
		add("SEC-DATA-01", "Data-at-rest protection", "required",
			"Application data directory mode 0700, files 0600, secrets in the OS keyring, encrypted backups, and SQLCipher/encrypted storage where the data model requires it.")
	}
	if ans.UntrustedInput || profile == "hostile-input" || profile == "hardened" || profile == "airgap" {
		add("SEC-LOG-01", "Log and crash hygiene", "required",
			"Redact logs, disable core dumps and third-party crash reporting, clear the clipboard on a timer, and never store secrets in localStorage. Treat parser input as radioactive.")
	}
	if network == "offline" || network == "allowlist" || profile == "airgap" {
		add("SEC-NET-01", "Default-deny egress", "required",
			"Block outbound network access by default, allowlist only reviewed endpoints, remove telemetry, and verify offline behavior with the network physically disconnected.")
	}
	if privilege != "none" || profile == "privileged-service" {
		add("SEC-PRIV-01", "Separate privilege from the UI", "required",
			"Never run the GUI as root/admin. Put capture/USB/raw-socket work in a dedicated service with only the required capabilities, use polkit for authorization, and write an audit log. Validate container/Flatpak compatibility before promising it.")
	}
	if hasAny(ans.Targets, "android", "ios") {
		add("SEC-MOBILE-01", "Mobile WebView and plugin hardening", "required",
			"No secrets in the JavaScript bundle, least-privilege native plugins, a hardened WebView configuration, and a review of certificate/transparency policy. Mobile is a separate delivery plan.")
	}
	if candidateID == "container" {
		add("SEC-NET-01", "Remote service exposure review", "required",
			"Container/remote PWA mode is network-facing. Require TLS, authentication, rate limits, patched base images, a non-root runtime user, and a documented backup/restore path.")
	}
	add("SEC-SUPPLY-01", "Supply-chain integrity", "required",
		supplyDetail(p))
	add("SEC-SIGN-01", "Artifact signing", requiredUnless(candidateID == "modernize", "required", "recommended"),
		signingDetail(ans.Targets))
	add("SEC-UPD-01", "Signed update path", requiredUnless(candidateID == "modernize", "required", "recommended"),
		updateDetail(network, profile))
	add("SEC-BUILD-01", "Reproducible clean builds", requiredUnless(profile == "hardened" || profile == "airgap" || profile == "hostile-input", "recommended", "required"),
		"Build in a clean container on the oldest supported glibc baseline, pin CI actions by commit SHA, publish checksums and a Sigstore bundle, and keep the build reproducible.")
	if desktopTarget && (hasAny(ans.Formats, "flatpak") || profile == "hardened" || profile == "airgap" || profile == "hostile-input") {
		status := "recommended"
		if hasAny(ans.Formats, "flatpak") {
			status = "required"
		}
		add("SEC-SANDBOX-01", "OS sandbox", status,
			"Flatpak/AppContainer with minimal permissions: no --filesystem=home, no --device=all, no --allow=devel. If privileged capture is required, document why the sandbox cannot be used.")
	}

	plan.Controls = dedupeControls(plan.Controls)
	plan.ResidualRisks = residualRisks(candidateID, server, profile, privilege, network)
	plan.Checklist = checklist(candidateID, server, privilege, ans.Targets)
	return plan
}

func supplyDetail(p *model.Project) string {
	languages := make(map[string]bool)
	if p != nil && p.Primary != nil {
		languages[p.Primary.Language] = true
	}
	parts := []string{"Commit lockfiles and install from them; do not resolve floating versions at build time."}
	if languages["node"] || (p != nil && hasCapability(p, "node")) {
		parts = append(parts, "Node: npm ci / pnpm install --frozen-lockfile; run npm audit and retire.js.")
	}
	if languages["python"] || (p != nil && hasCapability(p, "python")) {
		parts = append(parts, "Python: pip-compile --generate-hashes; run pip-audit.")
	}
	if languages["rust"] || (p != nil && hasCapability(p, "rust")) {
		parts = append(parts, "Rust: commit Cargo.lock; run cargo audit.")
	}
	if languages["php"] || (p != nil && hasCapability(p, "php")) {
		parts = append(parts, "PHP: commit composer.lock; run composer audit.")
	}
	parts = append(parts, "Generate a CycloneDX SBOM, scan with osv-scanner, and fail CI on critical/high findings.")
	return strings.Join(parts, " ")
}

func signingDetail(targets []string) string {
	var parts []string
	if hasAny(targets, "windows") {
		parts = append(parts, "Windows: Authenticode-sign the installer and binaries")
	}
	if hasAny(targets, "linux") {
		parts = append(parts, "Linux: sign artifacts with minisign/cosign/GPG")
	}
	if hasAny(targets, "macos", "ios") {
		parts = append(parts, "Apple: sign and notarize with a Developer ID")
	}
	if hasAny(targets, "android") {
		parts = append(parts, "Android: sign the APK/AAB with a protected release key")
	}
	if len(parts) == 0 {
		parts = append(parts, "Sign every artifact and publish verification instructions")
	}
	return strings.Join(parts, "; ") + ". Timestamp every signature and keep the private key offline."
}

func updateDetail(network, profile string) string {
	if network == "offline" || profile == "airgap" {
		return "Use a signed, manually imported update bundle with checksums and a documented removable-media procedure. Do not add a silent network update channel to an airgapped app."
	}
	return "Use signed updates over HTTPS with rollback protection, a pinned update endpoint, and a private key kept offline. Security-tool updates should never be silent."
}

func residualRisks(candidateID string, server bool, profile, privilege, network string) []string {
	risks := []string{
		"Upstream Electron, Tauri, WebKit, Chromium, or framework zero-days are outside Deskweaver's control.",
		"OS packages may be stale or tampered with; verify signatures and hashes before building.",
		"Malicious dependencies can pass lockfiles and vulnerability scanners; review new dependencies and maintainers.",
		"A compromised signing key or update channel defeats artifact signing and update integrity.",
		"A user who disables the sandbox, installs a rogue plugin, or runs as root can bypass technical controls.",
		"Physical access to an unlocked machine, and data copied outside the app (cloud sync, backups, screenshots), are out of scope.",
		"A generated configuration that was reviewed but not tested on the target OS may fail open or fail closed.",
	}
	switch candidateID {
	case "electron":
		risks = append(risks, "Bundled Chromium must follow Electron's release cadence; an outdated Electron is a known and patchable risk.")
	case "tauri", "wails", "pywebview", "neutralino":
		risks = append(risks, "Rendering and CVE exposure depend on the host WebView (WebKitGTK/WKWebView/WebView2) and its patch cadence.")
	case "pwa":
		risks = append(risks, "Browser storage can be evicted, and service-worker cache integrity and update behavior remain your responsibility.")
	case "container":
		risks = append(risks, "A remote/container deployment moves the attack surface to the network and host runtime; authentication, TLS, patching, and backups are mandatory.")
	case "modernize":
		risks = append(risks, "Packaging the current stack would ship known-EOL components; this plan intentionally stops at modernization.")
	case "privileged-service":
		risks = append(risks, "A compromise of the privileged service can exceed the UI's privileges; keep the service minimal, capability-scoped, and audited.")
	}
	if server {
		risks = append(risks, "A local HTTP boundary is reachable by same-user processes; token/origin checks reduce but do not eliminate that risk.")
	}
	if privilege != "none" {
		risks = append(risks, "Flatpak and capability-based capture can conflict; document the supported deployment matrix instead of promising both.")
	}
	if network == "open" {
		risks = append(risks, "Open network access increases remote attack surface; an explicit allowlist is strongly preferred.")
	}
	if profile == "hostile-input" {
		risks = append(risks, "Parser isolation cannot make arbitrary malware samples safe; use a disposable VM and assume breach.")
	}
	return dedupe(risks)
}

func checklist(candidateID string, server bool, privilege string, targets []string) []string {
	items := []string{
		"Review every generated file; Deskweaver generated it but did not execute or apply it.",
		"Commit lockfiles and pin CI actions by commit SHA.",
		"Run the conversion preflight script in dry-run mode before any build step.",
		"Build and test on a clean VM for every target operating system.",
		"Verify checksums and signatures after building, before distribution.",
		"Enable disk encryption and store secrets in the OS keyring, not in the repository.",
		"Remove telemetry and third-party crash reporting, or document the exception.",
		"Run OSV/Retire.js/pip-audit/cargo audit/composer audit in CI and fail on critical/high findings.",
	}
	if isWebShell(candidateID) {
		items = append(items, "Review CSP, navigation denial, and IPC allowlists together; a hole in one can defeat the others.")
	}
	if server {
		items = append(items, "Test the local API from a second unprivileged process: wrong token, wrong Origin, oversized body, and malformed input must all be rejected.")
	}
	if privilege != "none" {
		items = append(items, "Verify the service runs as a dedicated user with only the required capabilities; inspect audit logs and polkit rules.")
	}
	if hasAny(targets, "android", "ios") {
		items = append(items, "Run a mobile bundle-secret scan and review every native plugin permission.")
	}
	if candidateID == "modernize" {
		items = append(items, "Create the modernization plan and re-run Deskweaver after the EOL components are upgraded.")
	}
	return items
}

func capabilities(p *model.Project) map[string]bool {
	out := make(map[string]bool)
	if p == nil {
		return out
	}
	for _, c := range p.Capabilities {
		out[strings.ToLower(c)] = true
	}
	if p.Primary != nil {
		for _, c := range p.Primary.Capabilities {
			out[strings.ToLower(c)] = true
		}
	}
	return out
}

func hasServer(caps map[string]bool) bool {
	return caps["server"]
}

func isWebShell(id string) bool {
	switch id {
	case "tauri", "electron", "wails", "pywebview", "neutralino", "nativephp", "pwa", "capacitor", "cordova", "maui":
		return true
	default:
		return false
	}
}

func hasIPC(id string) bool {
	switch id {
	case "tauri", "electron", "wails", "pywebview", "neutralino", "nativephp", "capacitor", "cordova", "maui":
		return true
	default:
		return false
	}
}

func normalizeProfile(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "baseline", "standard", "dev", "development":
		return "baseline"
	case "hardened", "paranoid", "strict":
		return "hardened"
	case "airgap", "air-gapped", "offline":
		return "airgap"
	case "hostile-input", "hostile", "malware":
		return "hostile-input"
	case "privileged-service", "privileged":
		return "privileged-service"
	default:
		return "hardened"
	}
}

func normalizeSensitivity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "public", "internal", "confidential", "regulated":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "internal"
	}
}

func normalizeNetwork(n string) string {
	switch strings.ToLower(strings.TrimSpace(n)) {
	case "offline", "none", "airgap":
		return "offline"
	case "allowlist", "egress-allowlist", "restricted":
		return "allowlist"
	case "open", "internet", "lan":
		return "open"
	default:
		return "offline"
	}
}

func normalizePrivilege(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "none":
		return "none"
	case "privileged-service", "privileged", "root", "admin":
		return "privileged-service"
	case "raw-sockets", "packet-capture":
		return "raw-sockets"
	case "usb", "serial":
		return "usb"
	case "kernel", "driver":
		return "kernel"
	default:
		return "none"
	}
}

func requiredUnless(cond bool, ifTrue, ifFalse string) string {
	if cond {
		return ifTrue
	}
	return ifFalse
}

func hasAny(xs []string, wants ...string) bool {
	for _, x := range xs {
		for _, w := range wants {
			if strings.EqualFold(strings.TrimSpace(x), w) {
				return true
			}
		}
	}
	return false
}

func hasCapability(p *model.Project, want string) bool {
	return capabilities(p)[strings.ToLower(want)]
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

func dedupeControls(in []model.Control) []model.Control {
	index := make(map[string]int)
	out := make([]model.Control, 0, len(in))
	for _, c := range in {
		if i, ok := index[c.ID]; ok {
			if statusRank(c.Status) < statusRank(out[i].Status) {
				out[i].Status = c.Status
			}
			if !strings.Contains(out[i].Detail, c.Detail) {
				out[i].Detail += " " + c.Detail
			}
			continue
		}
		index[c.ID] = len(out)
		out = append(out, c)
	}
	return out
}

func statusRank(status string) int {
	switch status {
	case "required":
		return 0
	case "recommended":
		return 1
	default:
		return 2
	}
}

// Summary renders a short human-readable control summary.
func Summary(plan model.SecurityPlan) string {
	required, recommended, optional := 0, 0, 0
	for _, c := range plan.Controls {
		switch c.Status {
		case "required":
			required++
		case "recommended":
			recommended++
		default:
			optional++
		}
	}
	return fmt.Sprintf("%s profile: %d required, %d recommended, %d optional controls; %d residual risks.",
		plan.Profile, required, recommended, optional, len(plan.ResidualRisks))
}
