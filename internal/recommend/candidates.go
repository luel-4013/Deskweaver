package recommend

import "github.com/luel-4013/deskweaver/internal/model"

// Candidate is a conversion technology with a transparent score profile.
type Candidate struct {
	ID           string
	Name         string
	Kind         string
	Roles        map[string]int
	Security     int
	FeatureBase  int
	Platform     int
	Effort       int
	Maintenance  int
	Size         int
	Tradeoffs    []string
	Requires     []string
	SecurityNote string
	Architecture string
	OS           map[string]model.OSSupport
}

func support(os string, level int, formats []string, notes string) model.OSSupport {
	return model.OSSupport{OS: os, Level: level, Label: model.OSLabel(level), Formats: formats, Notes: notes}
}

// All returns the candidate catalog.
func All() []Candidate {
	return []Candidate{
		{
			ID: "tauri", Name: "Tauri 2", Kind: "native webview shell",
			Roles: map[string]int{
				"static": 35, "rust-server": 55, "go-server": 20, "node-server": 10,
				"python-server": 10, "hostile": 5, "privileged": 10, "mobile": 10,
			},
			Security: 92, FeatureBase: 45, Platform: 85, Effort: 60, Maintenance: 80, Size: 95,
			Tradeoffs: []string{
				"Requires a Rust toolchain and platform WebView libraries.",
				"WebKitGTK version and GPU-driver variance can break rendering.",
				"Not a good fit for apps that need a bundled Chromium or Node APIs.",
			},
			Requires:     []string{"rustc", "cargo", "node", "npm", "pkg-config", "webkit2gtk-4.1"},
			SecurityNote: "Smallest default attack surface: system WebView, explicit capabilities, no Node.js in the UI process.",
			Architecture: "Rust host + system WebView, with commands/capabilities instead of a Node bridge.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 3, []string{"flatpak", "deb", "rpm", "appimage", "tarball"}, "WebKitGTK 4.1 required."),
				"windows": support("windows", 3, []string{"nsis", "msi"}, "WebView2 runtime required."),
				"macos":   support("macos", 2, []string{"app", "dmg"}, "Build and sign on macOS."),
				"android": support("android", 2, []string{"apk", "aab"}, "Tauri v2 mobile; plugin coverage varies."),
				"ios":     support("ios", 2, []string{"ipa"}, "Requires macOS + Xcode."),
			},
		},
		{
			ID: "electron", Name: "Electron 45", Kind: "bundled Chromium shell",
			Roles: map[string]int{
				"static": 20, "node-server": 55, "python-server": 45, "php-server": 25,
				"laravel": 20, "ruby-server": 30, "go-server": 35, "dotnet-server": 40,
				"java-server": 30, "rust-server": 10, "hostile": 85, "privileged": 25,
				"cms": 5, "legacy": 5, "server": 50,
			},
			Security: 70, FeatureBase: 50, Platform: 92, Effort: 82, Maintenance: 75, Size: 40,
			Tradeoffs: []string{
				"Large bundle (100 MB+) and a bundled Chromium that must be patched.",
				"Broad Node.js/Electron attack surface; hardening is mandatory, not optional.",
				"Best compatibility for server sidecars and hostile input isolation.",
			},
			Requires:     []string{"node", "npm"},
			SecurityNote: "Bundled Chromium gives predictable rendering and a patchable engine, but requires contextIsolation, sandboxing, strict CSP, and no nodeIntegration.",
			Architecture: "Electron main process + sandboxed renderer; local servers run as isolated sidecars with a per-launch token.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 3, []string{"appimage", "deb", "rpm", "snap", "flatpak"}, "Flatpak needs care with sandboxing and sidecars."),
				"windows": support("windows", 3, []string{"nsis", "msi", "portable"}, "Authenticode-sign the installer."),
				"macos":   support("macos", 2, []string{"app", "dmg"}, "Build, sign, and notarize on macOS."),
				"android": support("android", 0, nil, "Not supported; Capacitor or a rewrite."),
				"ios":     support("ios", 0, nil, "Not supported; Capacitor or a rewrite."),
			},
		},
		{
			ID: "pwa", Name: "Progressive Web App", Kind: "browser-delivered app",
			Roles:    map[string]int{"static": 30, "cms": 20, "hostile": 5, "legacy": 5, "mobile": 20},
			Security: 62, FeatureBase: 45, Platform: 78, Effort: 95, Maintenance: 90, Size: 98,
			Tradeoffs: []string{
				"Not a native desktop app; no native filesystem or privileged APIs.",
				"Storage can be evicted; offline behavior is browser-dependent.",
				"iOS support is limited and installation is not equivalent to a desktop package.",
			},
			Requires:     []string{"node", "npm"},
			SecurityNote: "Same-origin browser sandbox with no native privileges, but CSP, service-worker integrity, and update strategy are on you.",
			Architecture: "Static web app plus manifest and service worker; no desktop host.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 2, []string{"browser"}, "Installable in Chromium/Firefox; no OS package."),
				"windows": support("windows", 2, []string{"browser"}, "Installable in Chromium/Edge; no OS package."),
				"macos":   support("macos", 2, []string{"browser"}, "Safari support is limited."),
				"android": support("android", 2, []string{"browser"}, "Installable; storage and background limits."),
				"ios":     support("ios", 1, []string{"browser"}, "Limited PWA capabilities; not a desktop parity target."),
			},
		},
		{
			ID: "capacitor", Name: "Capacitor 8", Kind: "mobile webview shell",
			Roles:    map[string]int{"mobile": 65, "static": 20, "node-server": 5},
			Security: 72, FeatureBase: 45, Platform: 70, Effort: 85, Maintenance: 80, Size: 75,
			Tradeoffs: []string{
				"Mobile-first: Android/iOS are first-class; desktop is not.",
				"Plugin coverage and native project maintenance are required.",
				"Store review, signing, and device testing add schedule risk.",
			},
			Requires:     []string{"node", "npm", "android-sdk", "xcode"},
			SecurityNote: "WebView sandbox plus native plugins; each plugin is part of the attack surface.",
			Architecture: "Web UI in a native Android/iOS shell with a typed plugin boundary.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 0, nil, "No first-class desktop target."),
				"windows": support("windows", 0, nil, "No first-class desktop target."),
				"macos":   support("macos", 0, nil, "No first-class desktop target."),
				"android": support("android", 3, []string{"apk", "aab"}, "Primary target."),
				"ios":     support("ios", 3, []string{"ipa"}, "Requires macOS + Xcode."),
			},
		},
		{
			ID: "cordova", Name: "Apache Cordova", Kind: "mobile webview shell",
			Roles:    map[string]int{"mobile": 40, "static": 10},
			Security: 45, FeatureBase: 35, Platform: 55, Effort: 60, Maintenance: 40, Size: 65,
			Tradeoffs:    []string{"Aging plugin ecosystem and slower release cadence.", "Prefer Capacitor for new mobile work."},
			Requires:     []string{"node", "npm", "android-sdk", "xcode"},
			SecurityNote: "Older WebView/plugin model; more maintenance and security debt than Capacitor.",
			Architecture: "Web UI in a Cordova WebView with native plugins.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 0, nil, "Not supported."),
				"windows": support("windows", 0, nil, "Not supported."),
				"macos":   support("macos", 0, nil, "Not supported."),
				"android": support("android", 2, []string{"apk", "aab"}, "Legacy path; verify plugin health."),
				"ios":     support("ios", 2, []string{"ipa"}, "Requires macOS + Xcode."),
			},
		},
		{
			ID: "wails", Name: "Wails 3", Kind: "Go native shell",
			Roles:    map[string]int{"go-server": 60, "static": 25, "node-server": 15, "hostile": 10},
			Security: 85, FeatureBase: 45, Platform: 82, Effort: 65, Maintenance: 72, Size: 90,
			Tradeoffs: []string{
				"Go-centric: the natural fit for Go backends, not for Node/Python apps.",
				"WebView variance is similar to Tauri.",
				"Smaller ecosystem than Electron or Tauri.",
			},
			Requires:     []string{"go", "node", "npm", "pkg-config", "webkit2gtk-4.1"},
			SecurityNote: "Go backend with a system WebView and a narrow binding layer; no Node.js runtime.",
			Architecture: "Go application host + WebView UI; backend methods are bound explicitly.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 3, []string{"deb", "rpm", "appimage", "tarball"}, "WebKitGTK required."),
				"windows": support("windows", 3, []string{"nsis", "msi", "portable"}, "WebView2 required."),
				"macos":   support("macos", 2, []string{"app", "dmg"}, "Build on macOS."),
				"android": support("android", 0, nil, "Not supported."),
				"ios":     support("ios", 0, nil, "Not supported."),
			},
		},
		{
			ID: "pywebview", Name: "pywebview 6", Kind: "Python webview shell",
			Roles:    map[string]int{"python-server": 50, "static": 20, "hostile": 10},
			Security: 65, FeatureBase: 45, Platform: 72, Effort: 78, Maintenance: 60, Size: 85,
			Tradeoffs:    []string{"Thin Python shell; limited packaging and auto-update story.", "WebView variance and Python runtime packaging remain."},
			Requires:     []string{"python3", "pip", "pkg-config", "webkit2gtk-4.1"},
			SecurityNote: "Python process plus a system WebView; keep the local API narrow and bind to loopback only.",
			Architecture: "Python process + system WebView; expose a small JS API surface.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 2, []string{"tarball", "deb"}, "WebKitGTK or Qt backend."),
				"windows": support("windows", 3, []string{"portable", "msi"}, "WebView2 or EdgeChromium backend."),
				"macos":   support("macos", 2, []string{"app", "dmg"}, "WKWebView."),
				"android": support("android", 0, nil, "Not supported."),
				"ios":     support("ios", 0, nil, "Not supported."),
			},
		},
		{
			ID: "neutralino", Name: "Neutralino", Kind: "lightweight webview shell",
			Roles:    map[string]int{"static": 25, "node-server": 15, "python-server": 10},
			Security: 55, FeatureBase: 40, Platform: 68, Effort: 82, Maintenance: 50, Size: 95,
			Tradeoffs:    []string{"Very small, but a smaller ecosystem and less mature hardening guidance.", "Native API coverage is limited."},
			Requires:     []string{"node", "npm"},
			SecurityNote: "Small native shell; review its native API surface and update cadence carefully.",
			Architecture: "Native shell + WebView with a JavaScript native API.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 2, []string{"appimage", "tarball"}, "WebKitGTK."),
				"windows": support("windows", 2, []string{"portable", "nsis"}, "WebView2."),
				"macos":   support("macos", 2, []string{"app"}, "WKWebView."),
				"android": support("android", 0, nil, "Not supported."),
				"ios":     support("ios", 0, nil, "Not supported."),
			},
		},
		{
			ID: "nativephp", Name: "NativePHP 2.5", Kind: "Laravel desktop shell",
			Roles:    map[string]int{"laravel": 80, "php-server": 10, "static": 5},
			Security: 68, FeatureBase: 45, Platform: 80, Effort: 68, Maintenance: 62, Size: 60,
			Tradeoffs: []string{
				"Laravel-specific; not a generic PHP wrapper.",
				"Bundles a PHP runtime and application; verify extension coverage.",
				"Younger ecosystem than Electron; test the packaging path early.",
			},
			Requires:     []string{"php", "composer", "node", "npm"},
			SecurityNote: "Bundled PHP runtime; disable debug mode, lock down storage, and avoid exposing the local server.",
			Architecture: "Laravel app + bundled PHP runtime + native window; keep the server bound to loopback.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 3, []string{"appimage", "deb", "rpm"}, "Check PHP extension parity."),
				"windows": support("windows", 3, []string{"nsis", "portable"}, "Check PHP extension parity."),
				"macos":   support("macos", 2, []string{"app", "dmg"}, "Build on macOS."),
				"android": support("android", 0, nil, "Not supported."),
				"ios":     support("ios", 0, nil, "Not supported."),
			},
		},
		{
			ID: "maui", Name: ".NET MAUI / Blazor Hybrid", Kind: "native .NET shell",
			Roles:    map[string]int{"dotnet-server": 55, "mobile": 50, "static": 15, "hostile": 10},
			Security: 78, FeatureBase: 45, Platform: 78, Effort: 55, Maintenance: 75, Size: 60,
			Tradeoffs:    []string{"Linux desktop is community-only; not a first-class target.", "Blazor Hybrid reuses components, not full Razor Pages."},
			Requires:     []string{"dotnet", "maui-workload"},
			SecurityNote: "Native .NET host with a WebView; MAUI's platform surface must be reviewed per target.",
			Architecture: "MAUI Blazor Hybrid components hosted in a native .NET app.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 0, nil, "Community-only; not a supported target."),
				"windows": support("windows", 3, []string{"msix", "exe"}, "Primary desktop target."),
				"macos":   support("macos", 2, []string{"app", "dmg"}, "Build on macOS."),
				"android": support("android", 3, []string{"apk", "aab"}, "Primary mobile target."),
				"ios":     support("ios", 3, []string{"ipa"}, "Requires macOS + Xcode."),
			},
		},
		{
			ID: "flutter", Name: "Flutter", Kind: "native UI rewrite",
			Roles:    map[string]int{"mobile": 55, "static": 15, "rewrite": 20},
			Security: 78, FeatureBase: 45, Platform: 85, Effort: 50, Maintenance: 80, Size: 55,
			Tradeoffs:    []string{"Not a web wrapper; the UI is rebuilt in Dart.", "Excellent platform coverage, but a rewrite is a rewrite."},
			Requires:     []string{"flutter", "dart", "android-sdk", "xcode"},
			SecurityNote: "Native UI with a smaller web attack surface, but a full rewrite and native dependency review.",
			Architecture: "Dart UI compiled to native platform code.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 2, []string{"deb", "appimage"}, "Desktop support is usable but less common."),
				"windows": support("windows", 3, []string{"msi", "portable"}, "Mature desktop target."),
				"macos":   support("macos", 3, []string{"app", "dmg"}, "Build on macOS."),
				"android": support("android", 3, []string{"apk", "aab"}, "Primary mobile target."),
				"ios":     support("ios", 3, []string{"ipa"}, "Requires macOS + Xcode."),
			},
		},
		{
			ID: "qt", Name: "Qt WebEngine", Kind: "C++/QML native app",
			Roles:    map[string]int{"static": 10, "native": 50, "rewrite": 20, "mobile": 10},
			Security: 80, FeatureBase: 40, Platform: 85, Effort: 40, Maintenance: 70, Size: 50,
			Tradeoffs:    []string{"Heavy native toolkit and licensing review (LGPL/GPL/commercial).", "WebEngine is desktop/embedded only; mobile is a Qt Quick rewrite."},
			Requires:     []string{"cmake", "qt", "compiler"},
			SecurityNote: "Mature native framework, but Qt WebEngine is a large C++ attack surface that needs its own patch cadence.",
			Architecture: "Qt/QML native shell with optional WebEngine view.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 3, []string{"deb", "rpm", "appimage"}, "WebEngine package required."),
				"windows": support("windows", 3, []string{"msi", "exe"}, "MSVC toolchain."),
				"macos":   support("macos", 3, []string{"app", "dmg"}, "Build on macOS."),
				"android": support("android", 1, []string{"apk"}, "Qt Quick rewrite, not a web wrapper."),
				"ios":     support("ios", 1, []string{"ipa"}, "Qt Quick rewrite; requires macOS."),
			},
		},
		{
			ID: "container", Name: "Container / Remote PWA", Kind: "service delivery",
			Roles:    map[string]int{"cms": 55, "do-not-package": 60, "node-server": 35, "python-server": 35, "php-server": 35, "ruby-server": 30, "go-server": 35, "dotnet-server": 30, "java-server": 35, "hostile": 20, "legacy": 5, "static": 10, "server": 45},
			Security: 65, FeatureBase: 45, Platform: 72, Effort: 88, Maintenance: 80, Size: 30,
			Tradeoffs:    []string{"Not a desktop app; requires a container runtime or a hosted service.", "Data locality and offline use are lost unless explicitly designed."},
			Requires:     []string{"container-runtime"},
			SecurityNote: "Server isolation can be strong, but the web/API surface is now remote and must be authenticated and patched.",
			Architecture: "Containerized service plus browser/PWA client; no native desktop shell.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 2, []string{"oci"}, "Container host."),
				"windows": support("windows", 2, []string{"oci"}, "WSL2/container host."),
				"macos":   support("macos", 2, []string{"oci"}, "Container host."),
				"android": support("android", 1, []string{"browser"}, "Remote client only."),
				"ios":     support("ios", 1, []string{"browser"}, "Remote client only."),
			},
		},
		{
			ID: "modernize", Name: "Modernize first", Kind: "modernization plan",
			Roles:    map[string]int{"legacy": 100, "rewrite": 40},
			Security: 90, FeatureBase: 80, Platform: 95, Effort: 5, Maintenance: 70, Size: 90,
			Tradeoffs:    []string{"No desktop app today; the upgrade/rewrite must happen first.", "This is the honest answer for EOL stacks, not a packaging recipe."},
			Requires:     nil,
			SecurityNote: "Modernizing removes known-EOL components before adding a new runtime or distribution channel.",
			Architecture: "Upgrade path first, then re-run Deskweaver for the modernized stack.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 3, nil, "Depends on the modernized stack."),
				"windows": support("windows", 3, nil, "Depends on the modernized stack."),
				"macos":   support("macos", 3, nil, "Depends on the modernized stack."),
				"android": support("android", 3, nil, "Depends on the modernized stack."),
				"ios":     support("ios", 3, nil, "Depends on the modernized stack."),
			},
		},
		{
			ID: "privileged-service", Name: "Unprivileged UI + privileged service", Kind: "split architecture",
			Roles:    map[string]int{"privileged": 80, "hostile": 20, "static": 10, "rust-server": 20, "go-server": 20},
			Security: 80, FeatureBase: 60, Platform: 85, Effort: 45, Maintenance: 65, Size: 80,
			Tradeoffs:    []string{"Two components: UI and a separately installed privileged service.", "IPC, authentication, audit logging, and packaging are the hard parts."},
			Requires:     []string{"rustc", "cargo", "systemd", "polkit"},
			SecurityNote: "Keep capture/privilege in a small service with explicit capabilities or polkit; the UI stays unprivileged and talks over a narrow IPC boundary.",
			Architecture: "Unprivileged Tauri/Electron UI + native privileged service (systemd/polkit) with scoped capabilities and audit logging.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 3, []string{"deb", "rpm", "flatpak-ui", "systemd-service"}, "UI in Flatpak; service installed separately."),
				"windows": support("windows", 2, []string{"msi", "service"}, "Windows service + UI; UAC boundary."),
				"macos":   support("macos", 2, []string{"app", "launchd"}, "Launchd helper; notarization."),
				"android": support("android", 0, nil, "Not applicable."),
				"ios":     support("ios", 0, nil, "Not applicable."),
			},
		},
		{
			ID: "rewrite", Name: "Native rewrite", Kind: "rewrite",
			Roles:    map[string]int{"rewrite": 60, "legacy": 20, "mobile": 30, "static": 10, "node-server": 30, "python-server": 30, "php-server": 30, "ruby-server": 30, "go-server": 30, "dotnet-server": 30, "java-server": 30, "hostile": 30, "privileged": 25, "server": 30},
			Security: 90, FeatureBase: 40, Platform: 95, Effort: 15, Maintenance: 70, Size: 85,
			Tradeoffs:    []string{"Largest effort; only justified when the web stack is the wrong long-term shape.", "You own native security, updates, and platform parity."},
			Requires:     nil,
			SecurityNote: "Can be the strongest security outcome, but only if the rewrite is funded and maintained.",
			Architecture: "Native application in the platform's preferred toolkit.",
			OS: map[string]model.OSSupport{
				"linux":   support("linux", 3, nil, "Native target."),
				"windows": support("windows", 3, nil, "Native target."),
				"macos":   support("macos", 3, nil, "Native target."),
				"android": support("android", 3, nil, "Native target."),
				"ios":     support("ios", 3, nil, "Native target."),
			},
		},
	}
}

// ByID returns a candidate by identifier.
func ByID(id string) (Candidate, bool) {
	for _, c := range All() {
		if c.ID == id {
			return c, true
		}
	}
	return Candidate{}, false
}
