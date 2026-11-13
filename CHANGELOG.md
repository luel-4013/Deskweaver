# Changelog

All notable changes to Deskweaver are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

No tagged release or signed binary exists yet. `0.1.0-dev` is a development
snapshot built from `main`.

## [Unreleased]

### Added

- Advisor-only CLI with `plan`, `scan`, `bundle`, `doctor`, `targets`, `explain`,
  `rules`, `self-check`, and `version` commands.
- Interactive wizard with an adaptive question set and a non-interactive,
  fail-closed mode for scripts and CI.
- Read-only project scanner with a bounded file walk, symlink skipping, and
  manifest parsing for Node, Python, Go, PHP, Java, .NET, Ruby, and Rust
  projects.
- Embedded 65-rule framework catalog across tiers A, B, and C, with
  evidence-bearing matches and a self-test corpus.
- 16 candidate delivery technologies with role-weighted scoring, S0-S4 OS
  support levels, trade-offs, fallbacks, and rejected alternatives.
- Threat-model controls for baseline, hardened, airgap, hostile-input, and
  privileged-service profiles, including residual-risk reporting.
- Review-only conversion kit with build plan, scaffold plan, command list,
  preflight script, security controls, packaging notes, SBOM notes, and an
  `ARTIFACTS.sha256` manifest.
- Atomic kit generation, refusal to overwrite a non-empty output directory,
  and timestamped backup with `--force`.
- Stable JSON output on stdout, JSON errors on stderr, and documented exit
  codes.
- Windows, macOS, and Linux build targets, cross-platform CI, GoReleaser
  configuration, checksums, and CycloneDX SBOM generation.
- Public documentation: conversion guide, security policy, contribution guide,
  code of conduct, changelog, and GitHub issue/PR templates.

### Fixed

- Go standard-library `net/http` servers are now detected as `go-http` instead
  of falling back to a low-confidence `static-web` match.
- CMS projects now treat the `cms` capability as a first-class scoring role, so
  WordPress and Drupal correctly recommend a container or remote PWA instead of
  a desktop shell.

### Security

- Advisor-only execution model: no installs, no elevation, no project writes,
  and no project-code execution.
- Generated scripts are scanned for forbidden destructive patterns and are
  never executed by Deskweaver.
- The development rule pack is integrity-checked with SHA-256 and reports
  `dev-unsigned`; it is not cryptographically signed.
- Release signing is intentionally not present. Do not describe current builds
  as signed.

[Unreleased]: https://github.com/luel-4013/deskweaver/commits/main
