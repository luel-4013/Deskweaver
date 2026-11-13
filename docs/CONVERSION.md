# Converting a project with Deskweaver

Deskweaver is an advisor, not a converter. It identifies what the project is,
recommends a delivery technology, explains the trade-offs, and writes a
review-only kit. It does **not** install dependencies, scaffold an app, modify
the project, build a package, sign it, or publish it.

The conversion itself happens after the review, using the official toolchain
for the recommended technology:

```text
scan -> plan -> review kit -> prepare host -> scaffold -> harden -> build
                                                              -> test
                                                              -> sign
                                                              -> distribute
        \_________________________/
          Deskweaver's job
```

This guide explains that handoff. It uses a generic React + Vite project as the
running example, but the same sequence applies to every recommendation.

## 0. Put the project under version control

Scaffolding and hardening change the project even though Deskweaver does not.
Commit or stash your work, create a branch, and make sure lockfiles are
committed before you start.

```sh
cd /path/to/project
git status
git switch -c desktop/tauri
```

No git repository? Make a full backup first. Do not experiment on the only copy
of your work.

## 1. Detect the project

```sh
deskweaver scan /path/to/project
```

Check the primary detection, tier, confidence, score, evidence, and detected
version. Also check capabilities such as `static`, `server`, `cms`, `legacy`,
`mobile-first`, and `native`.

If detection is wrong or absent, stop. A plan built on the wrong profile is
worse than no plan. Options:

- Run the interactive wizard and choose the manual profile.
- For a monorepo, select one workspace with `--workspace apps/web`.
- Add a rule only after you have sanitized evidence for it (see
  [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-framework-rule)).

## 2. Plan before generating a kit

Start with a plan and no kit:

```sh
deskweaver plan --no-input --target linux,windows --profile hardened --no-kit \
  /path/to/project
```

Use the interactive wizard when you want to be asked about data sensitivity,
untrusted input, network access, and privilege:

```sh
deskweaver
```

Read the recommendation, fallback, OS support matrix, trade-offs, rejected
alternatives, blockers, and host checks. Do not skip straight to the command
list.

Useful flags:

| Flag | Why it matters |
|---|---|
| `--target linux,windows` | Requested platforms. A candidate that cannot support one is rejected or blocked. |
| `--format deb,nsis` | Optional package formats; defaults come from the candidate and target. |
| `--profile baseline\|hardened\|airgap\|hostile-input\|privileged-service` | Selects the threat-model controls. Use `hardened` or stronger for real user data. |
| `--sensitivity public\|internal\|confidential\|regulated` | Describes the data the app handles. |
| `--untrusted-input` | Use when the app parses files, URLs, or network data from untrusted users. This can flip the recommendation, for example Tauri to Electron. |
| `--network offline\|allowlist\|open` | Describes the expected egress model. |
| `--privilege none\|raw-sockets\|usb\|privileged-service\|kernel` | Describes privileged features. Deskweaver requires stronger isolation for these. |
| `--candidate <id>` | Explicit override. It wins only if the candidate supports every requested target; blockers are still reported. |
| `--workspace <path>` | Analyze one workspace in a monorepo. |
| `--redact` | Removes absolute paths so a plan can be shared for review. |

Exit codes are part of the contract:

| Code | Meaning | What to do |
|---|---|---|
| `0` | Plan is complete and no blockers remain | Review the kit. |
| `1` | Invalid usage or an unsafe request | Fix the command; do not bypass the guard. |
| `2` | Project blockers remain | Resolve the blocker. CMS, legacy, unknown, and unselected monorepo cases are intentional stops. |
| `3` | Missing host dependencies | Install them from official sources, then rerun. |
| `4` | Unsupported target or target/format mismatch | Change the target/format or the candidate. |
| `5` | Internal error | Report it with the command and version. |
| `130` | Cancelled | No kit was written. |

A nonzero exit is not a warning to ignore. In particular, `3` means the plan
cannot be built on this host yet, and `2` means Deskweaver is deliberately
refusing to recommend a conversion path.

## 3. Generate and verify the kit

```sh
deskweaver plan --no-input --target linux,windows --profile hardened \
  --out /path/outside/project/deskweaver-out /path/to/project
```

The default output is `deskweaver-out/` in the current directory, or the
project's parent directory when the current directory is inside the project.
Nothing is written into the project. Use `--out` if you want the kit somewhere
explicit.

Verify the manifest before reading anything else:

```sh
cd /path/outside/project/deskweaver-out
sha256sum -c ARTIFACTS.sha256        # Linux
shasum -a 256 -c ARTIFACTS.sha256    # macOS
```

Read the kit in this order:

1. `plan.md` — verdict, evidence, OS matrix, trade-offs, blockers.
2. `security/SECURITY.md` and `security/controls.yaml` — required controls and
   residual risks for the selected threat model.
3. `conversion/build-plan.md` — build, test, and release sequence.
4. `conversion/scaffold-plan.md` — what the official scaffold must provide.
5. `conversion/commands.txt` — illustrative commands. They are not executed by
   Deskweaver and are not a substitute for the vendor's current documentation.
6. `conversion/preflight.sh` — host checks. Review it before running it.
7. `docs/REVIEW-CHECKLIST.md` and `docs/ROLLBACK.md` — review and rollback
   steps.
8. `packaging/<os>/README.md` — target-specific packaging notes.

Keep `plan.json` and `answers.yaml`. They are the reproducible record of the
decision:

```sh
deskweaver bundle deskweaver-out/plan.json --out ./review-kit
deskweaver plan --answers deskweaver-out/answers.yaml
```

`bundle` regenerates the kit without rescanning. It preserves the plan hash
when the decisions have not changed. `--answers` replays the full decision set;
relative paths in the answers file resolve from the file's directory.

## 4. Prepare the host

Run the doctor for the target you are building on:

```sh
deskweaver doctor --target linux --distro ubuntu-22.04
```

Deskweaver prints the checks and the install guidance it would use. It never
installs or elevates. Install only what the chosen toolchain needs, from the
vendor or your distribution, and verify checksums or signatures where they are
published.

Typical requirements:

| Technology | Host requirements |
|---|---|
| Tauri 2 | Rust toolchain (`rustc`, `cargo`), Node.js/npm, platform WebView development libraries (on Linux `webkit2gtk-4.1`), a C toolchain. Windows also needs WebView2 and the MSVC build tools; macOS needs Xcode Command Line Tools. |
| Electron | Node.js/npm and the Electron Forge toolchain. |
| Wails 3 | Go, Node.js/npm, and the platform WebView development libraries. |
| Capacitor | Node.js/npm, Android Studio and the Android SDK for Android; macOS and Xcode for iOS. |
| NativePHP | PHP, Composer, Node.js/npm, and the NativePHP desktop requirements. |
| Container / Remote PWA | A container runtime and a host or service to run it. No desktop shell is built. |
| Modernize | Nothing to package yet. Rewrite or upgrade the stack first. |

Avoid blind install scripts. In particular, do not pipe a remote script into a
shell. Prefer your distribution's packages, the vendor's signed installer, or
a verified release artifact. Pin tool versions where the project needs
reproducible builds.

## 5. Scaffold with the official toolchain

Deskweaver does not scaffold. The kit's `conversion/scaffold-plan.md` describes
the expected layout; the actual files come from the vendor CLI. Do this on the
branch you created in step 0.

### Server-backed projects (Flask, FastAPI, Django, Rails, Go HTTP)

A desktop recommendation for a server-shaped app does **not** mean the server
disappears into the shell. The native app becomes a client for a server that
must still run somewhere. Choose one architecture deliberately:

1. **Remote service:** host the backend behind TLS and authentication; the
   desktop shell loads the web UI or talks to the API. Data locality and
   offline use are lost unless you design for them.
2. **Local sidecar:** package the backend as a separate process, bind it to
   `127.0.0.1` (or a Unix socket/named pipe), give it a per-launch random
   token, validate `Origin`, and terminate it when the app exits. Never expose
   arbitrary shell, filesystem, or network primitives through the bridge.
3. **Rewrite the UI:** keep the backend remote and build a static frontend
   that talks to the API. This is often cleaner than embedding a web server.

For Python or PHP backends, Electron or Tauri plus a sidecar is usually more
honest than pretending the backend is a static site. The sidecar needs its own
packaging, signing, update, and crash-recovery plan. The kit's build plan and
review checklist call out this boundary; they do not implement it for you.

### Tauri 2 (React + Vite example)

For an existing web frontend:

```sh
npm install --save-dev @tauri-apps/cli@^2
npx tauri init
```

When prompted, use values that match the frontend:

- Frontend dev URL: `http://localhost:5173` (or the port Vite prints)
- Frontend dist: `../dist`
- Before dev command: `npm run dev`
- Before build command: `npm run build`

Then:

```sh
npm run tauri dev
npm run tauri build
```

For a new app, the official scaffold is:

```sh
npm create tauri-app@latest
```

Review `src-tauri/tauri.conf.json` and the generated capability files. The
kit's `security/tauri.conf.json` and `security/capabilities/default.json` are
review templates, not drop-in replacements.

### Electron

For an existing project, import it into Electron Forge. If the backend is
server-shaped, read [Server-backed projects](#server-backed-projects-flask-fastapi-django-rails-go-http)
first; Electron does not package the server for you.

```sh
npx electron-forge import
npm start
npm run make
```

For a new app, follow the official Forge template:

```sh
npm init electron-app@latest my-app
```

Review the main process, preload script, and renderer security settings before
adding any IPC.

### Wails 3

```sh
wails init -n my-app -t react-ts
cd my-app
wails dev
wails build
```

Use the template that matches the existing frontend, or follow the Wails guide
for adding Wails to an existing project.

### Capacitor

For an existing web build:

```sh
npm install @capacitor/core @capacitor/cli
npx cap init
npm install @capacitor/android
npx cap add android
npm run build
npx cap sync
npx cap open android
```

iOS requires macOS and Xcode:

```sh
npm install @capacitor/ios
npx cap add ios
npx cap open ios
```

Mobile targets are a separate delivery plan, not desktop parity. Test on real
devices and supported OS versions.

### NativePHP

NativePHP's package names and commands have changed across versions. Follow the
current official desktop guide rather than copying an old command from a blog
post:

<https://nativephp.com/docs>

### Container / Remote PWA

For a CMS or server-shaped project, Deskweaver recommends a container or remote
PWA on purpose. Do not wrap a PHP/WordPress/Drupal application in Electron just
to get a desktop icon.

The work is:

1. Package the service (Dockerfile or equivalent) with pinned base images.
2. Put it behind TLS and authentication.
3. Back up the database and uploaded files.
4. Provide a browser/PWA client; add a manifest and service worker only if you
   actually need installability or offline behavior.
5. Patch the server, runtime, and plugins on a schedule.

This is still a real conversion, but the deliverable is a service, not a native
shell.

### Modernize

If the recommendation is `modernize`, there is no kit. The detected stack is
too old or too coupled to a legacy runtime to package honestly. Plan the
rewrite or incremental upgrade first, then rerun Deskweaver on the result.

## 6. Apply the security controls

The kit derives controls from the threat model, not from a generic checklist.
Apply them before the first release.

- **Tauri:** keep the capability allowlist minimal, use a strict CSP, leave
  `withGlobalTauri` disabled, add permissions one at a time, and validate every
  IPC payload. Do not add the shell plugin unless the feature truly needs it.
- **Electron:** enable `contextIsolation` and `sandbox`, disable
  `nodeIntegration`, expose a narrow preload API, use a strict CSP, and never
  pass untrusted URLs or paths to `shell.openExternal` or filesystem APIs.
- **Local servers and sidecars:** bind to `127.0.0.1`, use a per-launch random
  token, validate the `Origin` header, terminate the child process on exit, and
  never forward arbitrary shell strings.
- **Data:** use the OS keyring for secrets, `0700` directories and `0600` files
  for application data, encrypted backups where the data model requires them,
  and never store secrets in `localStorage`.
- **Network:** default-deny egress, allowlist reviewed endpoints, and verify
  offline behavior with the network physically disconnected.
- **Supply chain:** commit lockfiles, install with `npm ci` or the equivalent
  frozen mode, pin CI actions, generate an SBOM, and fail the build on
  critical/high dependency findings.

Treat the generated files as a starting point for review. They are not a
certification, and they do not replace a threat model for your specific data
flows.

## 7. Build, test, and package

Build each target on its native OS or on a CI runner for that OS. Cross-building
a desktop shell is possible in some cases but is not a substitute for testing
on the target.

Test at minimum:

- clean install, first launch, and uninstall;
- launch with the network disconnected;
- malformed and hostile input;
- upgrade from the previous version;
- high-DPI scaling, multiple monitors, and both Wayland and X11 on Linux;
- file associations, autostart, and tray behavior if the app uses them;
- signature verification and checksum verification.

Package formats by target:

| Target | Common formats |
|---|---|
| Linux | AppImage, deb, rpm, Flatpak, tarball |
| Windows | NSIS, MSI, portable |
| macOS | app, DMG (plus notarization) |
| Android | APK for testing, AAB for distribution |
| iOS | IPA via Xcode |

Deskweaver does not sign releases. Set up your own signing keys, protect them,
and publish checksums and SBOMs alongside the artifacts. If you cannot verify a
signature, do not describe the build as signed.

## 8. End-to-end example

A React + Vite project on Linux, targeting Linux and Windows:

```sh
# 1. Detect and plan
deskweaver scan ~/repos/my-app
deskweaver plan --no-input --target linux,windows --profile hardened \
  --out ~/deskweaver-kits/my-app ~/repos/my-app

# 2. The example host is missing Rust, so this exits 3.
#    Install rustc/cargo and the WebKitGTK development package from official
#    sources, then rerun until the host check is clean.

# 3. Review the kit
cd ~/deskweaver-kits/my-app
sha256sum -c ARTIFACTS.sha256
less plan.md
less security/SECURITY.md
less conversion/build-plan.md

# 4. Scaffold on a branch
cd ~/repos/my-app
git switch -c desktop/tauri
npm install --save-dev @tauri-apps/cli@^2
npx tauri init

# 5. Develop, harden, and build
npm run tauri dev
npm run tauri build
```

The exact recommendation may differ. A project that handles untrusted input may
flip to Electron; a CMS will stop at a container/remote-PWA plan; a legacy
Tier C stack will stop for manual review.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `exit 3`, missing `rustc`/`cargo` | Rust is not installed | Install the Rust toolchain from the official source, then rerun the plan. |
| `exit 2`, CMS recommendation | WordPress/Drupal and similar are server apps | Use the container or remote-PWA plan; do not force Electron. |
| `exit 2`, monorepo | No workspace selected | Rerun with `--workspace apps/web` (or the correct path). |
| `exit 2`, Tier C legacy | No honest automatic path | Modernize first, or request a rule with sanitized evidence. |
| Tauri window is blank in dev | `devUrl` does not match the Vite port, or CSP blocks the dev server | Fix `build.devUrl`; use a development-only CSP. |
| Tauri build cannot find assets | `frontendDist` is wrong | Point it at the real build output (`../dist` for Vite). |
| `webkit2gtk-4.1` not found | Linux WebView development package is missing | Install the 4.1 development package for your distribution. |
| Electron renderer has no Node APIs | `nodeIntegration` is disabled, by design | Expose a narrow preload API instead of re-enabling Node integration. |
| Android build fails | SDK, JDK, or Gradle mismatch | Open the project in Android Studio and follow the Capacitor Android guide. |
| iOS build fails on Linux | iOS requires macOS and Xcode | Build on macOS or in a macOS CI runner. |
| Kit refuses to overwrite | The output directory is non-empty | Use a new `--out` path, or `--force` to move the old kit to a timestamped backup. |
| Plan contains absolute paths | Local paths are included by default | Use `--redact` before sharing the plan. |

## What Deskweaver will never do

- Install packages or run installers.
- Use `sudo` or any elevation mechanism.
- Write into the project directory.
- Execute project code, package scripts, or generated shell scripts.
- Claim that an unsigned build or rule pack is signed.
- Guarantee that a plan will build. Support levels are engineering judgments,
  not vendor guarantees.

If a generated file or command violates these rules, stop and report it
privately using [SECURITY.md](../SECURITY.md).

## Definition of done

- [ ] Detection and evidence reviewed; the project shape is correct.
- [ ] Recommendation, fallback, and trade-offs reviewed.
- [ ] All blockers resolved or explicitly accepted.
- [ ] Host dependencies installed and `deskweaver doctor` is clean.
- [ ] Kit checksums verified.
- [ ] Security controls applied and residual risks accepted.
- [ ] Scaffold built on a branch, not on `main`.
- [ ] Clean-VM install, launch, upgrade, and uninstall tested for every target.
- [ ] Offline and hostile-input behavior tested.
- [ ] Artifacts signed (if you sign), checksums and SBOM published.
- [ ] Rollback plan tested.

Deskweaver gets you to a reviewed decision. The official toolchain gets you to
a shipped application.
