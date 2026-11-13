# Security policy

## Supported versions

Deskweaver is in early development. No public release has been tagged yet, and
there are no signed binaries.

| Version | Supported |
|---|---|
| `main` (0.1.x development) | Yes |
| Older snapshots, forks, and generated kits | No |

Security fixes land on `main`. If a release is tagged later, this table will be
updated with the supported release line.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Use GitHub's private vulnerability reporting for this repository:

<https://github.com/luel-4013/deskweaver/security/advisories/new>

If private reporting is unavailable, email **luel-workneh@gmail.com** with the
subject prefix `[deskweaver security]`. Do not include secrets, private source
code, or third-party personal data in the report. Use a minimal, sanitized
reproduction instead.

Please include:

- Deskweaver version (`deskweaver version`) and how it was built or installed;
- operating system and architecture;
- the command that triggered the issue, with paths and project names redacted;
- what happened, what you expected, and the security impact;
- whether the issue is in the binary, the embedded rule/candidate catalog, the
  scanner, a generated kit, or the CI/release workflow;
- a minimal reproduction if one can be shared safely.

## What to expect

- We aim to acknowledge a report within 3 business days.
- We aim to complete an initial triage within 7 business days.
- Fix and disclosure timelines depend on severity and complexity. We will keep
  you informed and credit you if you want credit.
- There is no bug bounty program.

## Scope

In scope:

- the Deskweaver CLI and its embedded catalogs;
- the read-only scanner and rule evaluation;
- generated kit files that contain unsafe commands, incorrect security
  guidance, path traversal, or a way to make Deskweaver write outside the
  selected kit directory;
- violations of the advisor-only safety contract;
- CI or release workflow issues that could compromise a published artifact.

Out of scope:

- vulnerabilities in Tauri, Electron, Wails, Capacitor, NativePHP, Docker, or
  any other third-party toolchain;
- vulnerabilities in the project being scanned;
- reports that require the user to run an untrusted, modified copy of
  Deskweaver and then claim the modified behavior is ours;
- social engineering, physical access, or denial-of-service against GitHub;
- missing hardening that the generated plan already documents as a residual
  risk, unless the guidance itself is wrong or unsafe.

## Safety contract

Deskweaver is advisor-only by design:

- It does not install packages or run installers.
- It does not use `sudo` or any elevation mechanism.
- It does not write into the scanned project.
- It does not execute project code, package scripts, or generated shell
  scripts.
- It writes only the kit directory selected by the user, staged and committed
  atomically.
- An existing non-empty kit directory is refused unless `--force` is used,
  which moves the old directory to a timestamped backup instead of deleting it.
- Generated scripts are scanned for destructive patterns, but they remain
  review artifacts, not trusted automation.

If you find a path that violates any of these rules, treat it as a security
report.

## Known limitations that are not vulnerabilities

- The development rule pack is integrity-checked with SHA-256 but is **not**
  cryptographically signed. It reports `dev-unsigned`. Do not describe it as
  signed.
- Releases are not signed yet. Checksums and SBOMs do not replace a signature.
- EOL and framework-version checks are not implemented. A plan warns about this
  gap rather than claiming the version is supported.
- External rule packs are not supported in this build.
- The kit is an early review artifact. It is not a certification and does not
  replace a project-specific threat model.
- Support levels S0-S4 are engineering judgments, not vendor guarantees.

## Verifying a build

There are no official binaries yet. If you build from source, record the commit
and verify the module checksums with `go mod verify`. If release artifacts are
published later, verify `SHA256SUMS` and the documented signature before
running them. Never trust a binary solely because it has a Deskweaver name.
