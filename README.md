# Deskweaver

[![CI](https://github.com/luel-4013/deskweaver/actions/workflows/ci.yml/badge.svg)](https://github.com/luel-4013/deskweaver/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Deskweaver is a Linux-first, interactive CLI for planning a web project's
desktop or mobile conversion. It scans a local project read-only, detects what
the project actually is, recommends a delivery technology with evidence, shows
per-platform support levels, checks the host toolchain, and writes a
review-only security and conversion kit.

**Advisor only.** Deskweaver does not install packages, run project code, use
`sudo`, or modify your project. The only write is the kit directory you choose.

Status: **v0.1 development**. The converter is not shipped, the rule pack is
not signed, and no release artifacts exist yet. Read
[Known limitations](#known-limitations) before relying on a plan.

**New here?** [Converting a real project](docs/CONVERSION.md) explains the
handoff from a Deskweaver plan to Tauri, Electron, Wails, Capacitor, NativePHP,
or a container/remote-PWA plan.

## Why this exists

Most web-to-desktop tools are either a one-command wrapper that hides the hard
parts, or a framework CLI that assumes you already chose a framework.
Deskweaver covers the step before that: identify the project shape, compare the
realistic targets, surface the security consequences, and hand off to the
official toolchain with a plan you can review.

It is not a package manager, a runtime installer, or a replacement for Tauri
CLI, Electron Forge, or Capacitor.

## Quick start

Build from source (Go 1.27.1 or newer):

```sh
go build -o deskweaver ./cmd/deskweaver
```

Run the wizard in a real terminal:

```sh
./deskweaver
```

For a scripted, non-interactive plan:

```sh
./deskweaver plan --no-input --target linux,windows --profile hardened ~/repos/my-app
```

The plan is written to `deskweaver-out/` in the current directory, or to the
project's parent directory when the current directory is inside the project.
Nothing is written into the project itself.

## Convert a project

Deskweaver stops at a reviewed plan. The conversion is done with the official
toolchain:

1. `deskweaver scan <path>` to confirm detection and evidence.
2. `deskweaver plan --no-kit <path>` to review the recommendation, blockers,
   and exit code before writing anything.
3. `deskweaver plan <path>` to generate the kit, then verify
   `ARTIFACTS.sha256`.
4. Follow [docs/CONVERSION.md](docs/CONVERSION.md) to prepare the host,
   scaffold with the vendor CLI, apply the security controls, build, test, and
   package.

Deskweaver never executes the conversion. The guide includes a worked React +
Vite example, exit-code handling, host preparation, security controls, and a
release checklist.

## What it does

1. **Scans read-only.** Bounded file walk, symlinks skipped, no project code or
   package scripts executed.
2. **Detects the framework.** 65 declarative rules in tier A (deep), B
   (standard), and C (heuristic). A rule needs a discriminating signal, so a
   shared toolchain file such as `vite.config.ts` cannot produce a false
   Vue or Solid detection on its own.
3. **Recommends with evidence.** 16 candidate technologies, scored against the
   project profile and your threat model. Every recommendation shows its OS
   support levels, trade-offs, fallback, and rejected alternatives.
4. **Checks the host.** Linux distribution, package manager, session type, and
   allowlisted tool probes. It prints the install commands it would use; it
   never runs them and never elevates.
5. **Builds the security plan.** Controls and residual risks derived from the
   selected threat model, not a generic checklist.
6. **Writes a review kit.** Plan documents, a preflight script, packaging
   notes, templates, and a SHA-256 manifest. Scripts are generated but never
   executed.

### OS support levels

Every candidate is reported on all five targets with an explicit level:

| Level | Meaning |
|---|---|
| S0 | Unsupported |
| S1 | Experimental |
| S2 | Supported with caveats |
| S3 | Supported and tested |
| S4 | Hardened |

These are engineering judgments, not vendor guarantees. A high score never
overrides an S0 on a requested target; the tool reports the mismatch instead.

## Commands

| Command | Purpose |
|---|---|
| `deskweaver` | Interactive wizard (requires a terminal) |
| `deskweaver plan [path]` | Detect, recommend, check, and generate the kit |
| `deskweaver scan [path]` | Detection only |
| `deskweaver bundle [plan.json]` | Regenerate the kit from an existing plan |
| `deskweaver doctor` | Host readiness and cross-target guidance |
| `deskweaver targets` | Technology/platform support matrix |
| `deskweaver explain <id> [path]` | Rule or candidate evidence and reasoning |
| `deskweaver rules verify` | Verify the embedded rule pack |
| `deskweaver rules list` | List installed rule packs |
| `deskweaver rules test` | Run the rule self-test corpus |
| `deskweaver self-check` | Verify the binary's embedded catalogs |
| `deskweaver version` | Version and build metadata |

Run `deskweaver help` for the full flag list.

### JSON and CI

`--json` writes one stable JSON document to stdout and errors as JSON to
stderr. No progress text is mixed into stdout.

```sh
deskweaver plan --no-input --json --target linux . > plan.json
deskweaver doctor --target linux --distro ubuntu-22.04 --json
deskweaver targets --target linux,windows --json
```

Replay a reviewed decision set:

```sh
deskweaver plan --answers deskweaver-out/answers.yaml
```

The answers schema is strict: unknown fields are rejected rather than ignored.
Relative `project_path` and `output_dir` values resolve from the answers file,
not from the shell's working directory.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Invalid usage or unsafe request |
| 2 | Project blockers remain (manual review or no conversion path) |
| 3 | Missing required host dependencies |
| 4 | Unsupported target or target/format mismatch |
| 5 | Internal error |
| 130 | Cancelled |

## Generated kit

```text
deskweaver-out/
  README.md
  plan.md
  plan.json
  answers.yaml
  ARTIFACTS.sha256
  conversion/
    README.md
    build-plan.md
    commands.txt
    preflight.sh
    scaffold-plan.md
  docs/
    EXPECTED-OUTPUT.md
    REVIEW-CHECKLIST.md
    ROLLBACK.md
  packaging/
    linux/README.md
    windows/README.md
  security/
    SECURITY.md
    controls.yaml
    capabilities/default.json
    csp.txt
    tauri.conf.json
  ci/build.yml
  sbom/README.md
```

The exact file set depends on the candidate and selected targets.
`ARTIFACTS.sha256` covers every other generated file. The kit is staged and
committed atomically; an existing non-empty output directory is refused unless
`--force` is passed, which moves it to a timestamped backup instead of deleting
it.

## Safety contract

- No installs, no elevation, no project-code execution, no package scripts.
- Read-only scanning with a file-count bound; symlinks are skipped.
- The only write is the kit, and it is outside the project by default.
- Generated scripts contain no `sudo`, `curl | sh`, `rm -rf`, disk formatting,
  or world-writable permissions.
- Kit scripts are review artifacts. Deskweaver never runs them.
- The development rule pack is integrity-checked by SHA-256 but **not**
  cryptographically signed. The tool reports `dev-unsigned` and does not claim
  authenticity.

## Build and test

```sh
make check      # gofmt check, go vet, full test suite
make build      # static binary at ./deskweaver
make snapshot   # local GoReleaser snapshot in ./dist
```

`make snapshot` requires a git repository and GoReleaser v2. The release
workflow also uses Syft for SBOMs; a local snapshot without Syft needs
`--skip=sbom`.

The project has no CGO dependency. Release automation builds Linux, Windows,
and macOS archives for amd64 and arm64, publishes `SHA256SUMS`, and generates
CycloneDX SBOMs with Syft.

## Known limitations

- **EOL and version checks are not implemented.** Plans warn that the framework
  version has not been checked, and this gap should be closed before v1.0.
- **`--weight` is reserved but rejected.** It is never silently ignored. The
  recommendation text explains when a different security-versus-effort
  requirement could flip a close call.
- **External rule packs are not supported.** Only the embedded catalog is
  loaded. The signing design exists on paper, not in this build.
- **Wizard save/resume is not implemented.** The adaptive question count stays
  under the soft cap today; this becomes required before the question set
  grows.
- **No signed releases yet.** Signing, trademark clearance, and domain
  registration are launch blockers.
- **Release channels are not live.** There are no AUR, deb, rpm, winget, or
  Scoop packages, and no shell completions, man page, or update check yet.
- **The kit is an early review artifact.** It ships a preflight script, command
  list, and templates, not the full numbered install/build/verify/rollback
  script set described in the v1 design.
- **Windows is a second-class host in v0.1.** Its target support is reported
  fully, but host-specific checks and packaging have received less testing.
- **Support levels are judgments.** The tool tells you its evidence and its
  unknowns; it cannot prove an app will build.

## Documentation

- [Converting a project](docs/CONVERSION.md) — the real handoff to the official
  toolchain.
- [Architecture](docs/ARCHITECTURE.md) — how the packages and the read-only
  pipeline fit together.
- [Releasing](docs/RELEASING.md) — tag, draft release, verification, and
  signing status.
- [Contributing](CONTRIBUTING.md) — development setup, tests, and rule-authoring
  guidance.
- [Security policy](SECURITY.md) — private vulnerability reporting and the
  safety contract.
- [Changelog](CHANGELOG.md) — development history.
- [Code of conduct](CODE_OF_CONDUCT.md).

## License

Deskweaver is licensed under the [Apache License, Version 2.0](LICENSE). See
[NOTICE](NOTICE) for attribution.

Support levels, recommendations, and generated plans are engineering judgments,
not vendor guarantees. The software is provided on an "AS IS" basis without
warranties or conditions of any kind.
