# Contributing

Thanks for helping! Issues labelled
[`good first issue`](https://github.com/datosh/nixos-vex/labels/good%20first%20issue)
are a good place to start. Ask in the relevant issue if anything is unclear.

Security vulnerabilities in nixos-vex itself go through [private reporting](./SECURITY.md), not issues.

## Setup

You need Nix with flakes enabled.

```sh
nix develop .#ci   # python3, linters, gh
nix develop        # plus grype (with a ~3 GB DB) and sbomnix, for scanning
```

## Before you open a PR

```sh
make fmt    # nix fmt
make lint   # statix, deadnix, basedpyright, vexctl validate
make test   # nix flake check: personas, variants, conditions
```

Every PR must pass `ci`, `zero` and `zizmor`. `zero` regenerates the SBOM,
checks it against the committed one and fails on any untriaged finding (see
"Zero untriaged" in the [README](./README.md)).

A new condition in `modules/default.nix` needs a human-readable description,
a "restore with" hint where a config change restores it, and a negative test
in `checks/`.
