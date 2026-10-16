# Security policy

## Reporting a vulnerability

Report vulnerabilities in nixos-vex privately through GitHub:
[Report a vulnerability](https://github.com/datosh/nixos-vex/security/advisories/new)
(Security tab → "Report a vulnerability"). Please do not open a public issue
for them.

nixos-vex is a personal project. Reports are handled on a best-effort basis.

Only `main` is supported. There are no releases.

## In scope

- The GitHub workflows (`.github/workflows/`): anything that lets someone
  change the published feed, the committed SBOM or the repository without
  going through a reviewed PR, or that leaks a token.
- The NixOS module (`modules/default.nix`): evaluation that a crafted
  configuration can abuse, beyond a condition that is simply wrong (see
  below).
- The scripts (`scripts/`) and the pinned toolchain (`tools/`).

## Wrong verdicts are public issues

A statement in the feed that is wrong, including a `not_affected` or `fixed`
that hides a finding which does affect you, or a condition that holds although
the vulnerable code is reachable, is **not** a private report.

In this case, open an issue with the "Wrong verdict" template.

## Out of scope

The feed itself is not a security advisory. See the
[disclaimer](./README.md#disclaimer).
