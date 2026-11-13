# Contributing to Deskweaver

Thank you for helping improve Deskweaver. This project is in early development,
and the most useful contributions are reproducible bug reports, sanitized
project-shape evidence, documentation fixes, and well-tested rule changes.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Scope

Deskweaver is an **advisor-only** tool in v0.1. It detects, recommends, checks
the host, and writes a review kit. It does not convert a project, install
dependencies, or execute project code.

Before proposing a large feature, open an issue and explain:

- the problem it solves;
- why the existing plan/kit cannot solve it;
- whether it needs writes, installs, elevation, or execution (these conflict
  with the current safety contract and need an explicit design decision);
- how it behaves on Linux, Windows, and macOS.

## Safety invariants

These are non-negotiable for the v0.1 line:

1. No installs, no package-manager commands, no build execution.
2. No `sudo`, `doas`, polkit, or other elevation.
3. No writes into the scanned project. The only write is the selected kit
   directory.
4. No execution of project code, package scripts, or generated scripts.
5. Fail closed. Unknown input, unsupported targets, and missing dependencies
   must produce an error or blocker, not a silent guess.
6. Generated scripts and commands must not contain `sudo`, `curl | sh`,
   `rm -rf`, disk formatting, or world-writable permissions.
7. Never claim that an unsigned build, rule pack, or artifact is signed.
8. Do not weaken a target-support level or security control to make a
   recommendation look better.

If a change cannot satisfy these invariants, it belongs in a future major
version with a separate design and threat model, not in a quiet pull request.

## Development setup

Requirements:

- Go 1.27.1 or newer;
- `make` and a POSIX shell;
- git.

Optional:

- GoReleaser v2 for `make snapshot`;
- Syft for local SBOM generation;
- `actionlint` for workflow validation.

```sh
git clone https://github.com/luel-4013/deskweaver.git
cd deskweaver
make check
make build
./deskweaver self-check
```

## Tests and checks

Run these before opening a pull request:

```sh
make check                 # gofmt check, go vet, full test suite
go test -race ./...        # race detector
go build ./cmd/deskweaver  # local build
```

For changes that touch detection, recommendations, host checks, or generated
kits, also run:

```sh
./deskweaver rules verify
./deskweaver rules test
./deskweaver self-check
```

Cross-compile checks used by CI:

```sh
GOOS=windows GOARCH=amd64 go build ./cmd/deskweaver
GOOS=darwin  GOARCH=arm64 go build ./cmd/deskweaver
GOOS=linux   GOARCH=arm64 go build ./cmd/deskweaver
```

The repository has a local-only test bench under `testbench/`. It is
git-ignored because it contains absolute paths. Use it for manual and smoke
testing; do not commit it or generated kits.

## Project layout

| Path | Responsibility |
|---|---|
| `cmd/deskweaver` | Process entry point. |
| `internal/cli` | Flag parsing, command dispatch, JSON/error output. |
| `internal/app` | Orchestration: scan, recommend, doctor, security, kit. |
| `internal/scan` | Bounded read-only file walk and manifest parsing. |
| `internal/rules` | Embedded rule catalog, validation, matching, evidence. |
| `internal/recommend` | Candidate catalog, role weighting, scoring, blockers. |
| `internal/doctor` | Host readiness and target guidance. |
| `internal/security` | Threat-model controls and residual risks. |
| `internal/kit` | Atomic kit rendering, manifest, backup behavior. |
| `internal/ui` | Interactive wizard. |
| `internal/model` | Shared data types. |
| `internal/version` | Link-time build metadata. |

## Adding a framework rule

Rules are data, not code. Edit `internal/rules/catalog.json` and keep the
schema at `deskweaver.rules/v1`.

A rule has:

```json
{
  "id": "example-framework",
  "name": "Example Framework",
  "tier": "B",
  "language": "node",
  "default_target": "tauri",
  "priority": 50,
  "capabilities": ["static", "server"],
  "notes": "Short, honest guidance shown in the plan.",
  "signals": [
    {"kind": "manifest_dep", "manifest": "package.json", "name": "example-framework", "weight": 80},
    {"kind": "file_exists", "path": "example.config.*", "weight": 10}
  ]
}
```

Signal kinds:

| Kind | Fields | Meaning |
|---|---|---|
| `file_exists` | `path` (glob) | A file matching the glob exists. |
| `dir_exists` | `path` | A directory exists. |
| `manifest_dep` | `manifest`, `name` | A parsed manifest declares the dependency. |
| `file_contains` | `path` (glob), `pattern` (regex) | A small text file matches the pattern. |

Rules are additive and capped at 100. A rule needs at least one discriminating
signal with weight `>= 25`; shared toolchain files alone must not create false
positives. Use `supersedes` when a more specific rule should replace a generic
one, and keep `notes` factual rather than promotional.

Tier meanings:

- **A** — deep profile. Detection and recommendation are expected to be
  reliable; the candidate mapping is specific.
- **B** — standard profile. Detection is reliable, but the recommendation
  should be verified against the app shape.
- **C** — heuristic. Detection may be useful, but manual review is required and
  no automatic conversion should be promised.

After editing:

1. Add a regression test to `internal/scan/scan_test.go` using a minimal
   fixture.
2. Run `go test ./internal/scan ./internal/rules ./internal/recommend`.
3. Run `./deskweaver rules verify` and `./deskweaver rules test`.
4. If the rule changes a recommendation, add or update an engine test.
5. Update `docs/CONVERSION.md` only if user-facing behavior changes.

Do not include real project names, private source, absolute paths, or customer
data in fixtures or issues. Sanitize evidence first.

## Adding or changing a candidate technology

Candidates live in `internal/recommend/candidates.go`. A candidate needs:

- an ID and human-readable name;
- architecture, security note, trade-offs, and requirements;
- a role map used by the scoring engine;
- an OS support entry for all five targets (`S0` means unsupported);
- package formats for each supported target;
- a test in `internal/recommend/engine_test.go` for the project shapes where it
  should win or be rejected.

Do not add a candidate whose platform claims you cannot justify. A lower,
honest support level is better than an overclaim.

## Changing generated kits

Kit templates are in `internal/kit`. Generated scripts are review artifacts,
not automation. Before submitting:

- run the test bench smoke script;
- confirm the forbidden-command scan still passes;
- verify `ARTIFACTS.sha256` covers every generated file;
- confirm rerunning without `--force` refuses to overwrite;
- confirm `--force` moves the old directory to a timestamped backup instead of
  deleting it.

## Code style

- Run `gofmt`; CI rejects unformatted Go.
- Prefer the standard library and small, testable functions.
- Wrap errors with context (`fmt.Errorf("...: %w", err)`).
- Keep JSON output stable and document any schema change.
- Keep terminal output readable when piped; progress belongs on stderr.
- Do not add a dependency without a clear reason and a check that it builds on
  Linux, Windows, and macOS.
- Preserve deterministic ordering in output, tests, and generated files.

## Commits and pull requests

- Use a clear, focused commit. Conventional prefixes such as `fix:`, `feat:`,
  `docs:`, `test:`, and `chore:` are welcome.
- One logical change per pull request.
- Describe the safety impact in the pull request template.
- Include the commands you ran and their results.
- Do not commit build artifacts, generated kits, local planning documents,
  secrets, or absolute paths.

## Reporting bugs and security issues

- Bugs and feature requests: use the issue templates.
- Security vulnerabilities: follow [SECURITY.md](SECURITY.md). Do not open a
  public issue.

## License

Deskweaver is licensed under the Apache License, Version 2.0. By contributing,
you agree that your contribution is licensed under the same terms. See
[LICENSE](LICENSE) and [NOTICE](NOTICE).
