# Architecture

Deskweaver is a single static Go binary. It has no runtime service, no network
dependency, and no CGO requirement. The design goal is a **read-only pipeline
with an auditable decision record**, not a conversion engine.

## Pipeline

```text
cmd/deskweaver
      |
      v
internal/cli  -- parse flags, select command, render text or JSON
      |
      v
internal/app  -- orchestrate the plan
      |
      +--> internal/scan       read-only facts
      +--> internal/rules      framework hypotheses + evidence
      +--> internal/recommend  candidate scoring + blockers
      +--> internal/doctor     host readiness (no installs)
      +--> internal/security   threat-model controls + risks
      +--> internal/kit        render and atomically commit the kit
```

The interactive wizard is a thin front end over the same application path:
`internal/ui` collects decisions, then calls `internal/app`. The wizard does not
scan or write files itself.

## Package responsibilities

| Package | Responsibility |
|---|---|
| `cmd/deskweaver` | Process entry point and exit-code mapping. |
| `internal/cli` | Command dispatch, flag validation, stable JSON output, error formatting. |
| `internal/app` | Pipeline orchestration, decision assembly, plan hash, progress output. |
| `internal/scan` | Bounded file walk, symlink skipping, manifest parsing, fact base. |
| `internal/rules` | Embedded catalog, schema validation, rule matching, evidence. |
| `internal/recommend` | Candidate catalog, role weights, scoring, support matrix, blockers. |
| `internal/doctor` | Host OS/distro/session detection and allowlisted tool probes. |
| `internal/security` | Profile-driven controls, capability templates, residual risks. |
| `internal/kit` | Kit file rendering, checksum manifest, atomic commit, backup. |
| `internal/ui` | Adaptive interactive wizard. |
| `internal/model` | Shared types for detections, evidence, recommendations, plans. |
| `internal/version` | Link-time version, commit, and build date. |

## Read-only scanning

`internal/scan` walks the project with a file-count bound. It skips symlinks,
ignores common dependency and build directories, and reads only files needed
for detection and manifest parsing. It never executes package scripts, loads
plugins, or imports project code.

Manifests are parsed into a fact base:

- file and directory existence;
- declared dependencies and versions;
- a bounded set of small text files used by `file_contains` signals.

The fact base is the only input to rule evaluation, which keeps detection
deterministic and testable.

## Rules and evidence

`internal/rules/catalog.json` is embedded in the binary. Each rule is data:

- `tier` A, B, or C;
- `capabilities` used by the recommender;
- `signals` with a kind, target, regex or dependency name, and positive weight.

A rule matches only when at least one signal has weight `>= 25`. This prevents a
shared toolchain file such as `vite.config.ts` from producing false Vue or
Solid detections. Scores are additive and capped at 100. Every match carries
the evidence that produced it, and the plan prints that evidence.

The catalog is validated on load (`deskweaver rules verify`) and exercised by a
self-test corpus (`deskweaver rules test`).

## Recommendation

`internal/recommend` owns the candidate catalog and the scoring policy. The
engine:

1. derives roles from the detected framework and the answers (for example
   `static`, `server`, `cms`, `legacy`, `hostile`, `privileged`);
2. rejects candidates that do not support every requested target;
3. scores each eligible candidate with security, feature fit, platform support,
   effort, maintenance, and size weights;
4. selects a primary and fallback;
5. records rejected alternatives, trade-offs, blockers, and residual unknowns.

Role weighting is intentionally asymmetric: a technology that merely tolerates
a security-critical role must not tie one designed for it. A high score never
overrides an `S0` target or a blocker.

## Host checks

`internal/doctor` probes the host and selected targets. It reports missing
dependencies and the commands it *would* use, but it does not install anything
and does not elevate. The check is advisory: a missing dependency produces exit
code `3`, not a hidden workaround.

## Security model

`internal/security` maps the selected profile and answers to controls and
residual risks. Controls are rendered as review documents and templates, not
applied to the project. The generated capability/CSP/configuration files are
starting points for review; they are not drop-in replacements for a
project-specific threat model.

## Kit generation

`internal/kit` renders every file into a staging directory, computes the
`ARTIFACTS.sha256` manifest, and commits the directory atomically. If the target
directory is non-empty:

- without `--force`, the plan fails with exit code `1`;
- with `--force`, the old directory is renamed to a timestamped backup rather
  than deleted.

The kit is the only write. It is placed outside the project by default.

## Determinism and the plan hash

The plan hash covers the decision-relevant inputs and outputs: detection,
answers, recommendation, controls, target set, and generated artifact content.
Build timestamps, host discovery noise, and temporary paths are excluded. This
lets `deskweaver bundle plan.json` regenerate a kit and preserve the hash when
the decisions have not changed.

Output ordering is stable: rules, candidates, controls, and files are sorted
before rendering.

## Safety boundaries

The architecture enforces the product contract:

- no installer or package-manager code path;
- no elevation helper;
- no project write path;
- no project-code execution;
- no shell execution of generated scripts;
- no network access required for a plan.

The only subprocess probes are allowlisted, read-only host checks in
`internal/doctor`.

## Extension points

- **Framework detection:** add a rule to `internal/rules/catalog.json` plus a
  scanner test. No Go code is required for a new signal-based rule.
- **Candidate technology:** add or edit a candidate in
  `internal/recommend/candidates.go` plus an engine test.
- **Kit content:** edit templates in `internal/kit` and run the smoke test.
- **Answers schema:** extend `internal/app`/`internal/model` with strict
  validation; unknown fields must continue to be rejected.

External rule packs and a conversion executor are deliberately not part of this
architecture yet. They need a signing design, a plugin sandbox, and a separate
threat model.
