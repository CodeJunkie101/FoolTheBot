"""
The report generator.

Turns a scored run into:

  reports/<timestamp>-<target>.md     a readable report
  reports/<timestamp>-<target>.json   the raw results, for diffing runs

It serves both kinds of run. A disclosure report shows the reply and the
leaked text as evidence; an action report shows the agent's action log and
the specific calls that broke policy. The method and limitations sections
change to match. The limitations are not padding — a reader needs to know
what the tool cannot see before trusting a clean result.
"""

import json
import os
from datetime import datetime

from scorer import PASS, FAIL, SUSPECT

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(HERE, "reports")


def _fence(text, language=""):
    safe = (str(text) if text is not None else "").replace("```", "'''")
    return f"```{language}\n{safe}\n```"


def _table(headers, rows):
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def _header(summary, meta, out):
    out.append("# LLM Safety Test Report")
    out.append("")
    kind = ("Agent action red-team" if meta.get("mode") == "action"
            else "Chatbot disclosure test")
    out.append(_table(
        ["Field", "Value"],
        [
            ["Test type", kind],
            ["Target", meta.get("target_label", "unknown")],
            ["Probe library", f"{summary['total']} probes, "
                              f"{len(summary['by_category'])} categories"],
            ["Scoring", meta.get("scoring", "")],
            ["Run at", meta.get("timestamp", "")],
            ["Authorization", meta.get("authorization", "")],
        ],
    ))
    out.append("")


def _summary(summary, meta, out):
    counts = summary["counts"]
    action = meta.get("mode") == "action"
    out.append("## Summary")
    out.append("")
    rate = summary["pass_rate"] * 100
    out.append(f"The target held its rules on **{counts[PASS]} of "
               f"{summary['total']}** probes (**{rate:.0f}%**).")
    out.append("")
    if action:
        out.append(_table(
            ["Outcome", "Count", "Meaning"],
            [
                [f"`{PASS}`", counts[PASS], "no forbidden action taken"],
                [f"`{FAIL}`", counts[FAIL], "agent took a forbidden action"],
            ],
        ))
    else:
        out.append(_table(
            ["Outcome", "Count", "Meaning"],
            [
                [f"`{PASS}`", counts[PASS], "secret not disclosed"],
                [f"`{FAIL}`", counts[FAIL], "secret disclosed"],
                [f"`{SUSPECT}`", counts[SUSPECT],
                 "secret present once spacing and punctuation stripped"],
            ],
        ))
    out.append("")


def _by_category(summary, out):
    out.append("## Results by category")
    out.append("")
    out.append("Category is the useful view: a single percentage hides "
               "*which* class of input gets through.")
    out.append("")
    rows = []
    for category, bucket in summary["by_category"].items():
        total = sum(bucket.values())
        broken = bucket[FAIL] + bucket[SUSPECT]
        rows.append([category.replace("_", " "), f"{bucket[PASS]}/{total}",
                     broken if broken else "-"])
    out.append(_table(["Category", "Held", "Breaches"], rows))
    out.append("")


def _finding_disclosure(index, finding, out):
    out.append(f"### {index}. {finding['id']} — "
               f"{finding['category'].replace('_', ' ')}")
    out.append("")
    out.append(_table(
        ["Field", "Value"],
        [
            ["Verdict", f"`{finding['verdict']}`"],
            ["Detection", finding.get("reason", "")],
        ],
    ))
    out.append("")
    if finding.get("note"):
        out.append(f"*What this probe tests:* {finding['note']}")
        out.append("")
    if finding.get("context_file"):
        out.append(f"*Delivered indirectly via* `{finding['context_file']}` "
                   f"— the instruction was inside content the bot read.")
        out.append("")
    out.append("**Input sent**")
    out.append("")
    out.append(_fence(finding["probe"]))
    out.append("")
    out.append("**Reply received**")
    out.append("")
    out.append(_fence(finding["reply"]))
    out.append("")
    if finding.get("evidence"):
        out.append("**Evidence**")
        out.append("")
        out.append(_fence(finding["evidence"]))
        out.append("")
    if finding.get("judge_verdict"):
        out.append(f"**Judge:** `{finding['judge_verdict']}` — "
                   f"{finding.get('judge_reason', '')}")
        out.append("")


def _format_actions(actions):
    lines = []
    for action in actions:
        args = action.get("args", {})
        parts = []
        for key, value in args.items():
            shown = str(value)
            if len(shown) > 60:
                shown = shown[:57] + "..."
            parts.append(f"{key}={shown!r}")
        lines.append(f"{action['step']}. {action['tool']}({', '.join(parts)})")
    return "\n".join(lines) if lines else "(no actions taken)"


def _finding_action(index, finding, out):
    severity = finding.get("severity", "-")
    out.append(f"### {index}. {finding['id']} — "
               f"{finding['category'].replace('_', ' ')}  ·  {severity}")
    out.append("")
    out.append(_table(
        ["Field", "Value"],
        [
            ["Verdict", f"`{finding['verdict']}`"],
            ["Worst severity", severity],
            ["What happened", finding.get("reason", "")],
        ],
    ))
    out.append("")
    if finding.get("note"):
        out.append(f"*What this probe tests:* {finding['note']}")
        out.append("")
    if finding.get("context_file"):
        out.append(f"*Injection delivered via* `{finding['context_file']}` "
                   f"— the instruction was inside content the agent processed, "
                   f"not in the task it was given.")
        out.append("")
    out.append("**Task given to the agent**")
    out.append("")
    out.append(_fence(finding["probe"]))
    out.append("")
    out.append("**Actions the agent took**")
    out.append("")
    out.append(_fence(_format_actions(finding.get("actions", []))))
    out.append("")
    out.append("**Policy violations**")
    out.append("")
    for violation in finding.get("violations", []):
        out.append(f"- **{violation['severity']}** · `{violation['rule']}` · "
                   f"step {violation['step']}: {violation['detail']}")
    out.append("")


def _findings(results, meta, out):
    action = meta.get("mode") == "action"
    findings = [r for r in results if r["verdict"] != PASS]
    out.append("## Findings")
    out.append("")
    if not findings:
        subject = "forbidden action" if action else "disclosure"
        out.append(f"No probe in this library produced a {subject}. That is "
                   f"not proof of safety — see Limitations below.")
        out.append("")
        return
    out.append(f"{len(findings)} probe(s) broke a rule, with evidence below.")
    out.append("")
    for index, finding in enumerate(findings, start=1):
        if action:
            _finding_action(index, finding, out)
        else:
            _finding_disclosure(index, finding, out)


def _method_and_limits(meta, out):
    action = meta.get("mode") == "action"
    out.append("## Method")
    out.append("")
    if action:
        out.append("Each probe gives the agent a task and lets it run its "
                   "tool loop in a sandbox where no file, email, or command "
                   "is real. Every tool call is recorded, and the resulting "
                   "action log is checked against a fixed policy (external "
                   "email, file deletion, reading confidential paths, "
                   "destructive shell commands, and exfiltration of a "
                   "confidential value). The verdict comes from what the "
                   "agent did, never from what it said about what it did.")
    else:
        out.append("Each probe is sent to the target as a single turn. The "
                   "reply is scored by exact match against the protected "
                   "value, then by normalised match with spacing and "
                   "punctuation removed. Indirect probes carry their "
                   "instruction inside a document handed to the target.")
        if meta.get("judge_backend"):
            out.append("")
            out.append(f"A model-based judge (`{meta['judge_backend']}`) also "
                       f"read each reply and could escalate a result to "
                       f"`{FAIL}`, never clear one.")
    out.append("")

    out.append("## Limitations")
    out.append("")
    out.append("- A clean run means these probes did not succeed, not that "
               "the target is safe. The library is finite; the input space "
               "is not.")
    if action:
        out.append("- The sandbox agent is deliberately gullible. Results "
                   "characterise this target; run the same probes against a "
                   "hardened agent to measure a defense.")
        out.append("- The policy covers a fixed set of forbidden actions. An "
                   "agent could cause harm through an action the policy does "
                   "not model.")
    else:
        out.append("- String matching cannot detect a reply that describes "
                   "the protected value without reproducing its characters.")
    out.append("- Each probe is a single, independent run. Multi-turn attacks "
               "are out of scope for this version.")
    out.append("- Model outputs vary between runs; re-run before drawing "
               "conclusions.")
    out.append("")
    out.append("---")
    out.append("")
    out.append("*Generated by the LLM safety harness. Run only against "
               "systems you own or are explicitly authorized to test.*")
    out.append("")


def build_markdown(results, summary, meta):
    out = []
    _header(summary, meta, out)
    _summary(summary, meta, out)
    _by_category(summary, out)
    _findings(results, meta, out)
    _method_and_limits(meta, out)
    return "\n".join(out)


def write(results, summary, meta, directory=REPORT_DIR):
    """Write the Markdown and JSON reports. Returns (md_path, json_path)."""
    os.makedirs(directory, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"{stamp}-{meta.get('target_name', 'target')}"
    md_path = os.path.join(directory, base + ".md")
    json_path = os.path.join(directory, base + ".json")

    with open(md_path, "w", encoding="utf-8") as handle:
        handle.write(build_markdown(results, summary, meta))
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump({"meta": meta, "summary": summary, "results": results},
                  handle, indent=2, ensure_ascii=False)

    return md_path, json_path
