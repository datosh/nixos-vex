#!/usr/bin/env python3
"""The triage report the user signs off (reports/triage-<host>.md), which
then becomes the pull request description.

Run after `make scan`, `kernel-cna-triage.py <host>` and
`carry-forward.py <host> --dry-run` (`make triage` runs all four). Sections:

1. Deterministic: per rule (carry-forward rules, kernel classes for new
   CVEs), every finding it decides, and up to 3 of them sampled for a spot
   check with the evidence the rule used. Signed off per rule.
2. AI-proposed: every decision record in reports/decisions/, with its
   statement, its claims (checked by evidence.py: ok, FAIL, or "--" for the
   reviewer to follow), what would make it wrong and its re-check triggers.
   Signed off per finding.
3. Still untriaged: findings neither a rule nor a decision record covers.
4. Re-checks: carried `affected` verdicts, and acknowledged kernel findings
   whose draft is now an automatic `fixed` class.
5. Conversion candidates: reason classes of AI decisions (the triage log
   plus the pending records) seen at least 3 times; each is a candidate for
   a new deterministic rule.

Usage: triage-report.py <host> --vex <generated feed>
"""

import argparse
import json
import pathlib
import random
import sys
from collections import Counter, defaultdict
from typing import NoReturn, NotRequired, TypedDict, cast

from evidence import Claim, verify
from feed import Decision, Feed, check_decision, read_log
from zero import REPORTS, Report, db_built, load_acknowledged, triage

DECISIONS = REPORTS / "decisions"
NEW_CVE = "new CVE (no earlier verdict)"
SAMPLE = 3
CONVERT_AT = 3
AUTO_CLASSES = (
    "fixed-branch",
    "fixed-debian",
    "fixed-mainline",
    "fixed-changelog",
    "fixed-ancestor",
    "fixed-ubuntu",
    "not-present-version",
    "not-built-arch",
    "not-built-config",
    "affected-update",
)


class Done(TypedDict):
    rule: str
    cve: str
    purl: str
    severity: str
    statement: str
    detail: str
    written: NotRequired[dict[str, object]]


class Left(TypedDict):
    reason: str
    cve: str
    purl: str
    severity: str


class CarryResult(TypedDict):
    total: int
    done: list[Done]
    recheck: list[str]
    left: list[Left]


class KernelDraft(TypedDict):
    cve: str
    severity: str
    title: str
    klass: str
    evidence: list[str]
    statement: dict[str, object] | None
    cna: NotRequired[str]


def die(msg: str) -> NoReturn:
    print(f"triage-report: {msg}", file=sys.stderr)
    sys.exit(1)


def read_json(path: pathlib.Path, hint: str) -> object:
    try:
        return cast("object", json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError) as e:
        die(f"cannot read {path} ({hint}): {e}")


def short(purl: str) -> str:
    return purl.removeprefix("pkg:nix/")


def record_url(cve: str) -> str:
    return f"https://cveawg.mitre.org/api/cve/{cve}"


def statement_lines(st: dict[str, object]) -> list[str]:
    """The fields a reviewer reads, as a nested list."""
    keys = ("status", "justification", "impact_statement", "action_statement", "status_notes")
    out = [f"  - `{key}`: {st[key]}" for key in keys if key in st]
    products = cast("list[dict[str, str]]", st.get("products", []))
    if products:
        out.append(f"  - `products`: {', '.join(short(p['@id']) for p in products)}")
    return out


def sample[T](items: list[T], seed: str) -> list[T]:
    return random.Random(seed).sample(items, min(SAMPLE, len(items)))


def details(summary: str, body: list[str]) -> list[str]:
    return ["<details><summary>" + summary + "</summary>", "", *body, "", "</details>"]


def deterministic(
    carry: CarryResult, drafts: dict[str, KernelDraft], feed: Feed, seed: str
) -> tuple[list[str], set[tuple[str, str]]]:
    lines = ["## 1. Deterministic (sign off per rule)", ""]
    covered: set[tuple[str, str]] = set()
    by_rule: dict[str, list[Done]] = defaultdict(list)
    for d in carry["done"]:
        by_rule[d["rule"]].append(d)
    for rule, items in sorted(by_rule.items()):
        lines += [f"### carry-forward `{rule}` ({len(items)})", ""]
        lines += details(
            "All findings",
            [
                f"- {d['cve']} {short(d['purl'])} ({d['severity']}) → `{d['statement'].rsplit('#', 1)[1]}`"
                for d in items
            ],
        )
        lines += ["", "Spot checks:", ""]
        for d in sample(items, f"{rule}:{seed}"):
            if "written" in d:
                lines.append(f"- **{d['cve']}** {short(d['purl'])}: a new statement ([record]({record_url(d['cve'])}))")
                lines += statement_lines(d["written"])
            else:
                lines.append(
                    f"- **{d['cve']}** {short(d['purl'])}: the earlier verdict it extends ([record]({record_url(d['cve'])}))"
                )
                lines += statement_lines(feed.by_id(d["statement"]) or {})
            if (draft := drafts.get(d["cve"])) and short(d["purl"]).startswith("linux@"):
                lines.append(f"  - kernel draft `{draft['klass']}`: {'; '.join(draft['evidence']) or 'no evidence'}")
        lines.append("")

    # New kernel CVEs an automatic class decides: written with --apply <class>.
    new_kernel: dict[str, list[tuple[Left, KernelDraft]]] = defaultdict(list)
    for item in carry["left"]:
        draft = drafts.get(item["cve"])
        if (
            item["reason"] == NEW_CVE
            and short(item["purl"]).startswith("linux@")
            and draft
            and draft["klass"] in AUTO_CLASSES
            and draft["statement"]
        ):
            new_kernel[draft["klass"]].append((item, draft))
            covered.add((item["cve"], item["purl"]))
    for klass, pairs in sorted(new_kernel.items()):
        lines += [f"### kernel-cna-triage `{klass}`, new CVEs ({len(pairs)})", ""]
        lines += details(
            "All findings", [f"- {i['cve']} {short(i['purl'])} ({i['severity']}): {d['title']}" for i, d in pairs]
        )
        lines += ["", "Spot checks:", ""]
        for i, d in sample(pairs, f"{klass}:{seed}"):
            lines.append(f"- **{i['cve']}** {short(i['purl'])}: {d['title']} ([record]({record_url(i['cve'])}))")
            lines += [f"  - evidence: {e}" for e in d["evidence"]]
            lines.append("  - statement it writes:")
            lines += ["  " + s for s in statement_lines(cast("dict[str, object]", d["statement"]))]
        lines.append("")
    if not by_rule and not new_kernel:
        lines += ["Nothing.", ""]
    return lines, covered


def ai(decisions: list[tuple[pathlib.Path, Decision]], feed: Feed, severities: dict[tuple[str, str], str]) -> list[str]:
    lines = ["## 2. AI-proposed verdicts (sign off per finding)", ""]
    if not decisions:
        return [*lines, "Nothing.", ""]
    for path, d in decisions:
        purl = f"pkg:nix/{d['package']}@{d['version']}"
        sev = severities.get((d["cve"], purl), "not in the scan")
        st = d["statement"]
        verdict = "extend `" + d["extends"].rsplit("#", 1)[1] + "`" if "extends" in d else f"`{st.get('status')}`"
        lines += [f"### {d['cve']} {short(purl)} ({sev}): {verdict}", ""]
        lines.append(
            f"Finding type: {d['finding_type']}. Record: `{path.relative_to(REPORTS.parent)}`. [CVE record]({record_url(d['cve'])})"
        )
        lines += ["", "Proposed statement:", ""]
        if "extends" in d:
            lines += statement_lines(feed.by_id(d["extends"]) or {})
            if "status_notes" in st:
                lines.append(f"  - appended to `status_notes`: {st['status_notes']}")
        else:
            lines += statement_lines(st)
        lines += ["", "Claims (ok: checked by machine; --: follow the source):", ""]
        for n, claim in enumerate(d["claims"], 1):
            checked, detail = verify(Claim(**claim))
            result = checked.get("verified")
            mark = "--" if result is None else "ok" if result else "**FAIL**"
            src = claim["source"]
            where = f"[source]({src})" if src.startswith("https://") else f"`{src}`"
            lines.append(f"{n}. [{mark}] {claim['text']} ({where}; {detail})")
            if "excerpt" in claim:
                lines.append(f"   > {claim['excerpt']}")
        lines += ["", f"What would make it wrong: {d['counter_evidence']}"]
        if d.get("recheck"):
            lines.append(f"Re-check when: {'; '.join(d.get('recheck', []))}")
        if errors := check_decision(d, feed):
            lines += ["", "**Not applicable as it stands:** " + "; ".join(errors)]
        lines.append("")
    return lines


def rechecks(carry: CarryResult, drafts: dict[str, KernelDraft], acked: list[tuple[str, str]]) -> list[str]:
    lines = ["## 4. Re-checks", ""]
    if carry["recheck"]:
        lines += [
            f"Carried `affected` ({len(carry['recheck'])}): the stable ChangeLogs or release line show no fix yet.",
            "",
        ]
        lines += [*details("All", [f"- {r}" for r in carry["recheck"]]), ""]
    fixed_now = sorted(
        {
            cve
            for cve, purl in acked
            if short(purl).startswith("linux")
            and (d := drafts.get(cve))
            and d["klass"].startswith("fixed")
            and d["statement"]
        }
    )
    if fixed_now:
        lines += [
            "Acknowledged kernel findings whose draft is now an automatic `fixed` class (a corrected record or a found backport):",
            "",
        ]
        lines += [f"- {cve}: `{drafts[cve]['klass']}`, {'; '.join(drafts[cve]['evidence'])}" for cve in fixed_now] + [
            ""
        ]
    if len(lines) == 2:
        lines += ["Nothing.", ""]
    return lines


def candidates(decisions: list[Decision]) -> list[str]:
    seen: Counter[str] = Counter()
    examples: dict[str, list[str]] = defaultdict(list)
    for log in read_log():
        for e in log["events"]:
            if e["origin"] == "ai" and "decision" in e:
                rc = e["decision"].get("reason_class", "")
                seen[rc] += 1
                examples[rc].append(log["statement"].rsplit("#", 1)[1])
    for d in decisions:
        seen[d["reason_class"]] += 1
        examples[d["reason_class"]].append(f"{d['cve']}-{d['package']} (pending)")
    lines = ["## 5. Conversion candidates", ""]
    hits = [(rc, n) for rc, n in seen.most_common() if n >= CONVERT_AT and rc]
    if not hits:
        return [*lines, f"No reason class seen {CONVERT_AT} times yet.", ""]
    lines.append(
        "Reason classes decided by AI often enough to consider a rule (needs a machine-readable, authoritative source and a backtest against these decisions):"
    )
    lines.append("")
    lines += [f"- `{rc}` ({n}): {', '.join(examples[rc][:8])}" for rc, n in hits]
    return [*lines, ""]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    _ = parser.add_argument("host")
    _ = parser.add_argument("--vex", action="append", default=[], help="OpenVEX document the scan used (repeatable)")
    args = parser.parse_args()
    host = cast("str", args.host)
    vex_paths = cast("list[str]", args.vex)
    if not vex_paths:
        die("at least one --vex document is required")

    report = cast("Report", read_json(REPORTS / f"{host}.vulns.json", "run `make scan`"))
    carry = cast("CarryResult", read_json(REPORTS / f"carry-forward-{host}.json", "run carry-forward.py --dry-run"))
    drafts_path = REPORTS / f"kernel-triage-{host}.json"
    drafts = (
        {d["cve"]: d for d in cast("list[KernelDraft]", read_json(drafts_path, "run kernel-cna-triage.py"))}
        if drafts_path.exists()
        else {}
    )
    feed = Feed(dry_run=True)
    acked = [pair for path in vex_paths for pair in load_acknowledged(path)]
    n, untriaged = triage(report, acked)
    severities = {(u.cve, u.purl): u.severity for u in untriaged}
    decisions = [(p, cast("Decision", read_json(p, "decision record"))) for p in sorted(DECISIONS.glob("*.json"))]
    decided = {(d["cve"], f"pkg:nix/{d['package']}@{d['version']}") for _, d in decisions}

    built = db_built(report)
    lines = [
        f"# Triage: {host}",
        "",
        f"**{n} active, {n - len(untriaged)} acknowledged, {len(untriaged)} untriaged** before this triage "
        + f"(grype DB built {built}); carry-forward decides {len(carry['done'])}, {len(carry['left'])} are left for "
        + f"kernel classes, AI-proposed verdicts and review. Pending decision records: {len(decisions)}.",
        "",
    ]
    det, covered = deterministic(carry, drafts, feed, built)
    lines += det
    lines += ai(decisions, feed, severities)
    rest = [i for i in carry["left"] if (i["cve"], i["purl"]) not in covered | decided]
    lines += ["## 3. Still untriaged", ""]
    for i in rest:
        lines.append(f"- {i['cve']} {short(i['purl'])} ({i['severity']}): {i['reason']}")
        if short(i["purl"]).startswith("linux@") and (d := drafts.get(i["cve"])):
            lines.append(f"  - kernel draft `{d['klass']}`: {d['title']}; {'; '.join(d['evidence']) or 'no evidence'}")
    if not rest:
        lines.append("Nothing.")
    lines.append("")
    lines += rechecks(carry, drafts, acked)
    lines += candidates([d for _, d in decisions])

    out = REPORTS / f"triage-{host}.md"
    _ = out.write_text("\n".join(lines))
    print(f"triage-report: {len(rest)} still untriaged, {len(decisions)} decision record(s); report in {out}")


if __name__ == "__main__":
    main()
