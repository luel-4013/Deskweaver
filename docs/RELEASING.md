# Releasing Deskweaver

Deskweaver uses GoReleaser and GitHub Actions. A tag push starts the release
workflow, which tests the code, builds six archives (Linux, Windows, and macOS
on amd64 and arm64), writes `SHA256SUMS`, and generates CycloneDX SBOMs with
Syft. The GitHub release is created as a **draft**.

## Before tagging

1. `main` is green in CI.
2. `make check` passes locally.
3. `go test -race ./...` passes.
4. `./deskweaver self-check`, `rules verify`, and `rules test` pass.
5. `CHANGELOG.md` has an entry for the release.
6. No generated kits, local planning documents, testbench files, secrets, or
   absolute personal paths are tracked.
7. The version and commit metadata are injected by GoReleaser, not hard-coded
   in the source.

## Tag and push

```sh
git switch main
git pull --ff-only
git tag -a v0.1.0 -m "Deskweaver v0.1.0"
git push origin v0.1.0
```

Use semantic versioning. Prereleases use a suffix such as `v0.2.0-rc.1`; the
workflow marks them as prereleases automatically.

## After the workflow

1. Open the draft release and review the generated notes.
2. Verify the archive contents and that each archive includes `README.md`,
   `LICENSE`, and `NOTICE`.
3. Download `SHA256SUMS` and verify at least one archive:

   ```sh
   sha256sum -c SHA256SUMS --ignore-missing
   ```

4. Verify the SBOM files are present and attached to the release.
5. Check that the binaries report the expected version and commit:

   ```sh
   ./deskweaver version
   ```

6. Publish the draft only after the checks pass.

## Signing status

Release signing is **not implemented**. Do not describe a release as signed,
and do not add a placeholder key. An unsigned release with published checksums
is honest; a signed-but-unverifiable release is worse.

When signing is added, document the key, the verification command, and the
rotation/revocation procedure here before publishing the first signed release.

## If a release is wrong

- Keep the draft unpublished if possible.
- Delete the tag locally and remotely if it must be replaced:

  ```sh
  git tag -d v0.1.0
  git push origin :refs/tags/v0.1.0
  ```

- Fix the issue on `main`, run the full gate, and tag again.
- Never silently replace published artifacts. Publish a new patch release and
  explain the problem in the changelog.

## Not yet implemented

- Signed binaries and signed checksums.
- AUR, deb, rpm, winget, Scoop, or Flatpak release channels.
- Shell completions, a man page, and update checks.
- A stable release branch or backport policy.

These are launch tasks, not claims about the current build.
