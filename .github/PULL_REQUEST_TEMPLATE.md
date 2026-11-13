## Summary

<!-- What changed and why? Keep it focused. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Rule catalog or recommendation change
- [ ] Build, CI, or release change
- [ ] Refactor with no behavior change

## Safety checklist

- [ ] This change keeps Deskweaver advisor-only: no installs, no elevation, no
      project writes, and no project-code execution.
- [ ] Generated scripts and commands remain free of `sudo`, `curl | sh`,
      `rm -rf`, disk formatting, and world-writable permissions.
- [ ] Unknown input, unsupported targets, and missing dependencies still fail
      closed.
- [ ] No unsigned build, rule pack, or artifact is described as signed.
- [ ] No secrets, private source, customer data, or absolute personal paths are
      included.

If any box cannot be checked, explain why in the summary and request a design
review before merging.

## Test plan

<!-- List the commands you ran and their results. -->

```sh
make check
go test -race ./...
./deskweaver rules verify
./deskweaver rules test
./deskweaver self-check
```

## Documentation

- [ ] User-facing behavior is documented.
- [ ] `CHANGELOG.md` is updated for a notable change.
- [ ] No local-only material (`docs/planning/`, `testbench/`, generated kits,
      binaries) is included.

## Breaking changes

<!-- Describe any schema, exit-code, flag, or kit-layout change. Write "None" if not applicable. -->

## Related issues

<!-- Link issues with "Fixes #123" or "Refs #123". -->
