# CLAUDE.md

This file guides Claude Code (claude.ai/code) when working in this repository.

## What this is

nixos-vex is a VEX feed plus a NixOS module that cuts vulnerability-scanner
noise for NixOS systems, evaluated against each consumer's configuration.
Design and the consumer user story: `README.md`.

## Layout

| Path | Purpose |
|---|---|
| `flake.nix` | `nixosModules.default`, `nixosConfigurations.baseline`, `packages` (tools), `checks`, `formatter`, `devShells` (`ci`: python3, linters, gh; `default`: plus grype with the 3 GB DB and sbomnix) |
| `vex/baseline.openvex.json` | The statements, the source of every generated feed. Written only through `scripts/feed.py` |
| `triage/` | The triage log: one file per statement, every decision that wrote it (origin, sign-off, AI claims) |
| `tools/default.nix`, `tools/pins.json` | The pinned scan toolchain: `.#grype` (with `.#grype-db`), `.#sbomnix` (with a pinned CPE dictionary), and `.#vexctl` (unreleased `main` for `validate`, updated by hand). `pins.json` holds the DB and cpedict pins; `make bump` moves them on a branch, the zero gate decides. |
| `modules/default.nix` | Conditions, `system.build.vexFeed`, warnings, `nixosVex.strict`, `nixosVex.dropped` |
| `checks/default.nix` | `nix flake check`: the demo personas and reference-system variants evaluated with the current module and feed |
| `demo/desktop/`, `demo/server/` | Consumer flakes with a remote, pinned nixos-vex; their READMEs are updated by hand |
| `hosts/baseline/` | Reference system: stock `nixos-generate-config` output. Never edit `configuration.nix` beyond formatting |
| `sboms/baseline.cdx.json` | Committed SBOM of the reference system (`make sbom`) |
| `.claude/skills/triage/` | The triage skill: the whole triage process, from preview to hand-off |
| `scripts/feed.py` | The one writer of the feed and the triage log; `feed.py apply` writes signed-off AI decision records |
| `scripts/evidence.py` | Checks the claims of a decision record against their sources |
| `scripts/triage-report.py` | `make triage`: the report the user signs off, later the PR description |
| `scripts/kernel-cna-triage.py` | Drafts kernel verdicts (CNA data, stable ChangeLogs, Debian tracker, Kbuild/.config) |
| `scripts/carry-forward.py` | `make carry-forward`: decided verdicts extended to the versions a bump brought in; rules in its docstring |
| `scripts/triage-links.py` | One CVE: its matches in `reports/`, research links, `--check-nixpkgs`, `--cna-contact` |
| `scripts/bump.py` | `make bump`: every pin to its latest (flake inputs, cpedict, grype DB) |
| `scripts/zero.py` | The zero-untriaged check over `reports/<host>.vulns.json` (`make zero`) |
| `scripts/sbom-check.py`, `scripts/impact.py` | The zero gate: the committed SBOM equals a fresh one (apart from serial and timestamp); what a PR changes against the base feed |
| `scripts/daily-report.py` | The daily run's job summary and tracking-issue body |
| `.github/workflows/` | `daily.yml` (`make bump` uncommitted, tracking issue), `ci.yml` (fmt, lint, flake checks), `zero.yml` (the zero gate), `zizmor.yml` (auditor persona) |
| `.github/rulesets/main.json` | Ruleset for main: PRs only, `ci`/`zero`/`zizmor` required, no bypass |

## Commands

```bash
make test                                                # nix flake check: personas, variants, shadowing, strict, conditions (checks/)
make fmt                                                 # nix fmt (treefmt + nixfmt, nixfmt-tree from the pinned nixpkgs)
make lint                                                # statix, deadnix (stock configuration.nix excluded), basedpyright, vexctl validate --strict (source and generated feed)
nix build .#nixosConfigurations.baseline.config.system.build.vexFeed
make sbom                                                # sboms/baseline.cdx.json (skipped if the closure is unchanged)
make scan                                                # grype with the generated feed -> reports/baseline.vulns.json
make zero                                                # scan, then scripts/zero.py: fails on any untriaged finding
make bump                                                # on a branch: every pin to its latest, new SBOM, scan
make triage                                              # preview for sign-off: scan, kernel drafts, carry-forward --dry-run -> reports/triage-baseline.md
make carry-forward                                       # carry decided verdicts forward; report -> reports/carry-forward-baseline.md
make gate                                                # what CI requires: regenerate the SBOM, check the committed one, scan the regenerated one, zero
nix develop .#ci -c python3 scripts/triage-links.py CVE-2026-12345 --check-nixpkgs --cna-contact
nix develop .#ci -c python3 scripts/kernel-cna-triage.py baseline  # drafts -> reports/kernel-triage-baseline.{json,md}
nix develop .#ci -c python3 scripts/kernel-cna-triage.py baseline --apply fixed-branch CVE-2026-12345
nix develop .#ci -c python3 scripts/feed.py apply reports/decisions/CVE-2026-12345-linux.json
nix develop .#ci -c basedpyright                           # after EVERY Python edit
```

## Working agreements

- **Sign-off protocol:** triage follows the triage skill
  (`.claude/skills/triage/`). Nothing reaches the feed before the user signs
  it off: deterministic rules per rule (with spot checks), AI verdicts per
  finding. Every new condition gets a negative test.
- **The user commits.** Never commit, push or amend on their behalf unless
  asked. Draft, never send, anything outward-facing (PRs, upstream emails,
  issues).
- **Python:** run basedpyright after every edit and fix findings with real
  types (TypedDict, narrowing), never suppressions. Scripts are stdlib-only.
- **"Zero untriaged"**, not "zero CVEs": every active grype finding at every
  severity is either suppressed (`not_affected`/`fixed`) or acknowledged
  (`affected` + `action_statement`). Always state it together with the grype DB
  build date.
- **No gate or policy for consumers.** Consumers own policy. This repo owns
  the feed, the module, the reference system, the triage tooling and its own
  zero check.
- **Main is always at zero untriaged** (at its committed pins). Every change,
  pin bumps included, goes through a PR that must pass `ci`, `zero` and
  `zizmor`. The cycle: daily alert → branch → `make bump` → triage skill
  (`make triage`, sign-off, apply) → PR with `reports/triage-baseline.md` →
  gates → merge.
- **One triage round is one PR, one commit per batch** (bump and SBOM,
  carry-forward, kernel classes, each group of AI verdicts), so each batch
  can be reviewed on its own. The PR is squash-merged, so main moves from
  zero to zero in one commit.

## Statement conventions

- **IDs:**
  - doc `@id` = the GitHub blob URL of the feed file
  - statement `@id` = doc `@id` + `#CVE-<id>-<pkg>`; a second statement for
    the same CVE and package (a changed verdict at a later version) appends
    the version: `#CVE-<id>-<pkg>-<version>`
  - IDs are immutable once minted
  - the document `version` and `last_updated` move on every change, once per
    PR (main is what is published)
  - a new statement carries `timestamp` (the day it was written; the
    document's timestamp predates it), a changed one `last_updated`. No
    statement `version` for now: go-vex (grype, vexctl) drops it
  - `feed.py` applies all of the above; never edit statements by hand
- **Write plain-language evidence.** Name the function or file, the version
  that fixes it, and the sources (CNA record URL, ChangeLog, commit). Internal
  labels (kernel draft classes, reason classes) never appear in statements.
- **Purls:**
  - versioned (`pkg:nix/linux@6.18.54`) when the verdict depends on the code
    or build of this version: `fixed`, `affected`, code absent in this
    version, every code-reading verdict, and every kernel build-config
    verdict (nixpkgs' kernel config changes between versions; `stock-kernel`
    does not pin it)
  - versionless (`pkg:nix/linux`) when it holds for any version nixpkgs could
    ship: upstream-disputed, wrong product, distro-only patch, another
    architecture, and verdicts that rest only on NixOS configuration
    conditions (a filesystem is not mounted, a service is not running); say
    why in `status_notes`
  - a verdict carried to a later version adds that version's purl to the
    statement's `products` (`make carry-forward`), rather than a new statement
- **Justifications in use:**
  - `vulnerable_code_not_present`
  - `vulnerable_code_not_in_execute_path`
  - `vulnerable_code_cannot_be_controlled_by_adversary`
  - `component_not_present`
  - `inline_mitigations_already_exist`
- **`affected` statements need an `action_statement`:** the fix route (which
  version or backport) plus a concrete NixOS mitigation where one exists
  (e.g. `boot.blacklistedKernelModules`).
- **Conditional statements:**
  - carry `[nixos-vex:condition=<id>]` in `status_notes`, one marker per condition
  - the impact text names the conditions in words
  - a new condition goes in `modules/default.nix` with a human-readable
    description and a "restore with" hint where a config change restores it
  - unknown ids fail evaluation; unused ones fail `checks.conditions`
- **Watched records:** `[vexlint:watch_record=<dateUpdated>]` marks a
  statement that relies on a CNA record we believe is stale. The daily run
  reports when the record's `dateUpdated` changes; re-check the statement then.
- **Choose conditions conservatively.** A condition must be false whenever the
  vulnerable code could become reachable, e.g. a filesystem counts as mountable
  if autofs is on or any mount uses `auto`.

### Choosing the verdict

- **`fixed` or `not_affected`.**
  - `fixed`: the flaw existed upstream and the version we ship contains its
    fix: an upstream fix commit that is an ancestor of our release, release
    notes of a version at or below ours, or a nixpkgs patch. Also when the
    scanner's range is wrong (a CNA or NVD range without an upper bound).
  - `not_affected` / `vulnerable_code_not_present`: the vulnerable code never
    existed in what we build: a distro-only or out-of-tree patch, another
    product (CPE mismatch), another architecture (`x86-64`), a build option
    nixpkgs leaves off (`stock-kernel`), or a flaw introduced after our
    version.
- **Code reading is enough for `not_affected` only when the argument is
  structural**, each step quoted from the source at our tag: the code is not
  compiled (Kconfig, Makefile), has no caller in our tree, is only matched on
  another platform (device tree on x86), or sits behind an entry-point gate
  (`capable()`, a file mode). Arguments about runtime behaviour (a race
  cannot happen, an error path is unreachable, which values a table or
  firmware produces, what an allocation failure or device reset does) lead to
  `affected`. So does "it needs hardware X": no condition can check hardware,
  so `affected` with a blacklist mitigation. Mark every verdict that rests on
  code reading with "CODE-READING ONLY" in its `counter_evidence`.
- **Privilege gates (`vulnerable_code_cannot_be_controlled_by_adversary`)**
  when reaching the code needs a capability in the initial user namespace
  (`capable()`, not `ns_capable()`) or a root-only device node, and NixOS
  grants it to no service or user by default. NixOS has no root-to-kernel
  boundary (nixpkgs builds without the lockdown LSM), so a flaw only root can
  trigger gives an attacker nothing new. Name the gate in the impact
  statement. It does not apply when:
  - a NixOS module grants the capability (e.g. CAP_NET_ADMIN to
    NetworkManager), unless a condition checks that the service is off
  - udev rules can widen a node's mode, unless a condition checks them (like
    `nvme-nodes-privileged`)
  - the access can be delegated by default (namespaced capabilities, user
    namespaces); a delegation that needs an administrator's action, such as
    a BPF token, does not count

## Triage evidence sources

- **Kernel:**
  - kernel.org CNA records (per-branch semver plus `programFiles`)
  - the shipped branch's stable ChangeLogs on cdn.kernel.org
  - GitHub compare to test whether a fix commit is an ancestor of the shipped tag
  - Debian security tracker JSON (trust its `fixed_version`; treat its
    "not affected" as a hint only, since it reflects Debian's config). Its
    per-CVE page has notes the JSON lacks
  - Ubuntu CVE tracker (`git.launchpad.net/ubuntu-cve-tracker/plain/{active,retired,ignored}/<CVE>`):
    its `break-fix:` lines map old CVEs without a kernel.org record to their
    fix commits
  - Kbuild Makefile → `.config` and `modules.dep` (is the code built, built-in or a module?)
- **NVD:** NVD enrichment often collapses stable branches into one range; the
  CNA record is authoritative.
- **Userland:**
  - nixpkgs patches applied to the package
  - sbomnix patch pedigree (the pedigree rule of `carry-forward.py`)
  - upstream release branches
  - Debian tracker
  - CNA records
- **Check NixOS defaults in the evaluated config, not from memory,** e.g.
  `security.allowUserNamespaces`, the `/dev/kvm` mode, LSMs on the kernel
  command line, `kernel.core_pattern`, `networking.firewall.checkReversePath`.
