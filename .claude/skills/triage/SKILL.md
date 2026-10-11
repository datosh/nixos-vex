---
name: triage
description: Triage the reference system's untriaged grype findings to zero. Deterministic rules first, AI-researched decision records for the rest, the user signs off (rules per class, AI verdicts per finding), feed.py writes the statements and the triage log. Use when the daily tracking issue reports findings, after `make bump`, or when asked to triage CVEs.
---

# Triage

The statement conventions, the rules for choosing a verdict ("Choosing the
verdict") and the evidence sources are in `CLAUDE.md`; this skill does not
repeat them. Read them before writing any statement text.

## Principles

- **Rules before AI.** What a script can decide from data, a script decides
  (`kernel-cna-triage.py`, `carry-forward.py`, the SBOM patch pedigree). The
  AI researches only what is left.
- **The user is the judge.** Nothing reaches the feed before sign-off:
  deterministic output per rule (with spot checks), AI verdicts per finding.
  The AI may propose any valid statement; the evidence must let the user
  walk from the CVE to the verdict without trusting the AI.
- **One writer.** Statements are written only by `feed.py` (and the scripts
  built on it), never by editing `vex/baseline.openvex.json` by hand. Every
  write lands in the triage log (`triage/`).
- **Inconclusive evidence means `affected`.** When the research is done but
  cannot show the code is fixed, absent or unreachable, propose `affected`
  with an `action_statement` (the fix route, a NixOS mitigation where one
  exists). Not `under_investigation`: when the research is not done, the
  pull request stays open.

## Steps

### 1. Branch and preview

Work on a bump branch (`bump/<date>`), never on main. If the pins have not
moved yet, run `make bump` first.

```bash
make triage    # scan, kernel drafts, carry-forward --dry-run, reports/triage-<host>.md
```

Read `reports/triage-baseline.md`:
- section 1: what the rules decide, per rule
- section 3: what is left for you to research

### 2. Research each finding of section 3

Sort the finding into one **finding type** first, because the type decides
the sources:

| Type | Question | First sources |
|---|---|---|
| `matching-error` | Did the scanner match the wrong software or version? | the SBOM component (purl, CPE), the CVE's CPE configuration, the upstream project |
| `version-range` | Is our version inside the affected range, or is the fix in it? | CNA record per-branch data, stable ChangeLogs, upstream release branches, nixpkgs patches at the pin |
| `reachability` | Is the vulnerable code built, loaded and reachable on NixOS? | Kbuild and `.config`, `modules.dep`, NixOS defaults in the evaluated config, the vulnerable function's callers |
| `no-upstream-fix` | Is there a fix anywhere yet? | CNA record, upstream tracker or list, Debian tracker |

The kernel draft in section 3 already says what the script found (e.g.
`manual-module`: the file is built as a module). Start from it.

Write one **decision record** per finding to
`reports/decisions/<CVE>-<pkg>.json`:

```json
{
  "cve": "CVE-2026-12345",
  "package": "linux",
  "version": "6.18.55",
  "finding_type": "reachability",
  "reason_class": "module-needs-hardware",
  "statement": {
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "impact_statement": "Plain-language evidence per CLAUDE.md ...",
    "status_notes": "[nixos-vex:condition=...]"
  },
  "claims": [
    {
      "text": "The CNA record names drivers/foo/bar.c as the only program file.",
      "source": "https://cveawg.mitre.org/api/cve/CVE-2026-12345",
      "excerpt": "drivers/foo/bar.c"
    },
    {
      "text": "The fix is not in 6.18.55: its commit is absent from the 6.18.55 ChangeLog.",
      "source": "https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.18.55",
      "check": {"type": "absent", "needle": "0123456789ab"}
    },
    {
      "text": "The flaw was introduced by commit abcdef..., which is in v6.18.",
      "source": "https://git.kernel.org/stable/c/abcdef...",
      "check": {"type": "ancestor", "repo": "torvalds/linux", "commit": "abcdef...", "ref": "v6.18"}
    }
  ],
  "counter_evidence": "What would make this verdict wrong, concretely.",
  "recheck": ["the CNA record's dateUpdated changes", "nixpkgs enables CONFIG_FOO"]
}
```

- **`statement`**: `status` plus the fields that status needs
  (`not_affected`: `justification` and `impact_statement`; `affected`:
  `action_statement`). `products` defaults to the versioned purl; give it
  only for a versionless purl, and say why in `status_notes`. To extend an
  existing statement instead (same verdict, new version), set
  `"extends": "<its @id>"` and give only a `status_notes` sentence saying why
  the new version is covered.
- **Claims**: one fact each, in the order the reasoning goes. The source is
  primary (the CNA record API, the commit on git.kernel.org, the ChangeLog,
  the nixpkgs file at the pinned revision on GitHub, the Debian tracker
  JSON), never a summary site. Give an `excerpt` (verbatim from the source)
  or a `check` wherever possible; a claim without one is for the user to
  follow. The check types are in `scripts/evidence.py`'s docstring:
  - `absent` with `sources` for "in none of these files" (e.g. every
    stable ChangeLog of the branch up to ours)
  - `ancestor` / `not_ancestor` for "the fix is (not) in this release"
  - `eval` for a NixOS option or package-set fact of the reference system
    (`config.services.openssh.enable`, `pkgs` with `"apply": "p: p ? opie"`)
  - `build` for a line in a built file: a Kconfig value
    (`config.boot.kernelPackages.kernel.configfile`, `"line":
    "CONFIG_SMC=m"`, or `"no_line_prefix": "CONFIG_X="` for not set), a
    module alias (`config.system.modulesTree`, `"path":
    "lib/modules/*/modules.alias"`)

  For `eval` and `build`, `source` names what was evaluated
  (`nix:<attr>`). Facts about the kernel source tree (a caller, a function)
  cite the file on git.kernel.org at our tag with an `excerpt`.
- **`reason_class`**: a short kebab-case label for why the verdict holds,
  internal only. Reuse an existing one when it fits:
  `jq -r '.events[].decision.reason_class // empty' triage/*.json | sort | uniq -c`.
- **`counter_evidence`**: what would have to be true for the verdict to be
  wrong. Say it even when you consider it unlikely. Start it with "CODE-READING ONLY:" when
  reading code is the only argument for the verdict.
- **New conditions**: if the verdict needs a new `[nixos-vex:condition=...]`,
  say so in the presentation; the condition is code (`modules/default.nix`)
  and gets a negative test.

Check the claims, and fix any failing one before presenting:

```bash
nix develop .#ci -c python3 scripts/evidence.py reports/decisions/*.json
```

### 3. Present for sign-off

Regenerate the report with the decision records:

```bash
nix develop .#ci -c python3 scripts/triage-report.py baseline \
  --vex "$(nix build --no-link --print-out-paths .#nixosConfigurations.baseline.config.system.build.vexFeed)"
```

In the conversation give a short table: per rule, the count and its spot
checks; per finding, the proposed verdict in one line. Point to
`reports/triage-baseline.md` for the evidence chains. Ask for:
- each rule: approve or reject (a rejected rule is a bug in a script: stop,
  and fix the rule as a code change)
- each finding: approve, amend (the user's verdict replaces the proposal;
  edit the record and apply it with `--amended`) or reject (research more)

### 4. Apply what was signed off

In this order:

```bash
make carry-forward                                                     # approved carry-forward rules
nix develop .#ci -c python3 scripts/kernel-cna-triage.py baseline --apply <class>...   # approved kernel classes, new CVEs
nix develop .#ci -c python3 scripts/feed.py apply reports/decisions/<file>.json...    # approved findings
nix develop .#ci -c python3 scripts/feed.py apply --amended reports/decisions/<file>.json  # amended ones
```

`feed.py` refuses records that are incomplete or whose checks fail, bumps
the document version once per branch, and logs every decision under
`triage/`. Delete the applied records from `reports/decisions/`.

### 5. Verify

```bash
make lint      # vexctl validate --strict included
make test      # plus a negative test for every new condition
make gate      # zero untriaged
```

State the result with the grype DB build date.

### 6. Hand off

The user commits (feed, `triage/`, pins, SBOM, any condition). The pull
request description is `reports/triage-baseline.md` (sections 1 to 4) and
`reports/carry-forward-baseline.md`.

### 7. Conversion candidates

If section 5 of the report lists a reason class, propose a rule, do not
build it: which machine-readable, authoritative source would decide it, and
a backtest of that rule against the logged decisions of the class (it must
agree with every one). The user decides whether it becomes code.

### Re-checks

Section 4 lists carried `affected` verdicts and acknowledged kernel
findings whose draft is now an automatic `fixed` class. A newly `fixed`
verdict for the same version is a new statement (`feed.py` appends the
version to the `@id`) through a decision record like any other.
