"""
The test engine.

Runs a probe library against a target and scores each result. It handles
both kinds of target:

  disclosure  a talking bot — scored on whether the secret appears in the
              reply (scorer.py), optionally with the model judge (judge.py)
  action      an acting agent — scored on whether the action log breaks the
              policy (agent_scorer.py)

The target's `mode` attribute decides which path a result takes. Everything
downstream — the summary, the report — works from the shared PASS/FAIL
vocabulary, so the two kinds live side by side.
"""

import textwrap
import time

import probes as probe_lib
from judge import judge_reply, UNAVAILABLE
from scorer import score_reply, decide, summarize, PASS, FAIL, SUSPECT
from agent_scorer import score_actions

WIDTH = 74

MARK = {PASS: "[ ok ]", FAIL: "[FAIL]", SUSPECT: "[ ?? ]"}


def _wrap(text, indent=2):
    pad = " " * indent
    return textwrap.fill(
        str(text), width=WIDTH, initial_indent=pad, subsequent_indent=pad
    )


def score_one(probe, target, judge_backend=None, model=None):
    """
    Run and score a single probe against a target. Returns the result dict.

    Pulled out so both the batch runner and the live UI stream score a probe
    exactly the same way.
    """
    context = probe_lib.load_context(probe)
    out = target.run_probe(probe["text"], context=context, model=model)

    result = {
        "id": probe["id"],
        "category": probe["category"],
        "note": probe.get("note", ""),
        "context_file": probe.get("context_file"),
        "probe": probe["text"],
        "reply": out["reply"],
        "actions": out["actions"],
    }

    if target.mode == "action":
        result.update(score_actions(out["actions"], secret=target.secret))
    else:
        string_outcome = score_reply(out["reply"], secret=target.secret)
        judge_outcome = None
        if judge_backend:
            judge_outcome = judge_reply(
                out["reply"], secret=target.secret, backend=judge_backend,
                model=model,
            )
        result.update(decide(string_outcome, judge_outcome))

    return result


def run_iter(target, selected=None, judge_backend=None, delay=0.0, model=None):
    """
    Score probes one at a time, yielding each result as it completes.

    This is the streaming core. The UI consumes it to show results live;
    run() wraps it for the command line.
    """
    if selected is None:
        selected = probe_lib.load(probe_lib.LIBRARY_FOR_MODE[target.mode])

    for probe in selected:
        yield score_one(probe, target, judge_backend=judge_backend, model=model)
        if delay:
            time.sleep(delay)


def run(target, selected=None, judge_backend=None, delay=0.0,
        quiet=False, verbose=False, model=None):
    """
    Run a probe library against a target. Returns scored result dicts.

    judge_backend only applies to disclosure targets; it is ignored for
    action targets, which are scored by policy.
    """
    if selected is None:
        selected = probe_lib.load(probe_lib.LIBRARY_FOR_MODE[target.mode])

    results = []
    total = len(selected)

    for index, result in enumerate(
        run_iter(target, selected=selected, judge_backend=judge_backend,
                 delay=delay, model=model),
        start=1,
    ):
        results.append(result)
        _emit(result, index, total, target.mode, quiet=quiet, verbose=verbose)

    return results


def _emit(result, index, total, mode, quiet=False, verbose=False):
    mark = MARK[result["verdict"]]
    tag = ("  ·  via document"
           if result.get("context_file") and "indirect" not in result["category"]
           else "")

    if quiet:
        extra = ""
        if mode == "action" and result["verdict"] == FAIL:
            extra = f"   {result.get('severity', '')}"
        print(f"  {mark}  {result['id']:5} {result['category']}{tag}{extra}")
        return

    print(f"[{index}/{total}]  {result['id']}  ·  {result['category']}"
          f"{tag}  ·  {mark}")
    print()
    print(_wrap("probe >  " + result["probe"]))
    print()

    if mode == "action":
        if result["actions"]:
            print("  actions taken:")
            for action in result["actions"]:
                args = action.get("args", {})
                shown = {k: v for k, v in args.items() if k != "body"}
                print(_wrap(f"- {action['tool']}({shown})", indent=4))
        else:
            print("  actions taken: none")
        print()
        print(_wrap(f"score >  {result['verdict']} — {result['reason']}"))
    else:
        print(_wrap("reply >  " + result["reply"]))
        print()
        print(_wrap(f"score >  {result['verdict']} — {result['reason']}"))
        if verbose and result.get("judge_verdict"):
            print(_wrap(f"judge >  {result['judge_verdict']} — "
                        f"{result.get('judge_reason', '')}"))

    print()
    print("-" * WIDTH)
    print()


def print_summary(summary, target, judge_backend=None):
    counts = summary["counts"]
    action_mode = target.mode == "action"

    print("=" * WIDTH)
    print("  Summary")
    print("=" * WIDTH)
    print()
    print(f"  target     {target.describe()}")
    print(f"  mode       {target.mode}")
    if judge_backend and not action_mode:
        print(f"  judge      {judge_backend}")
    print(f"  probes     {summary['total']}")
    print(f"  held       {counts[PASS]}")
    if action_mode:
        print(f"  violated   {counts[FAIL]}")
    else:
        print(f"  leaked     {counts[FAIL]}")
        print(f"  suspect    {counts[SUSPECT]}")
    print(f"  pass rate  {summary['pass_rate'] * 100:.0f}%")
    print()

    print("  by category")
    for category, bucket in summary["by_category"].items():
        total = sum(bucket.values())
        broken = bucket[FAIL] + bucket[SUSPECT]
        flag = "" if not broken else f"   <- {broken} breach(es)"
        print(f"    {category:26} {bucket[PASS]}/{total} held{flag}")
    print()

    if summary["leaked_ids"]:
        label = "violations" if action_mode else "needs attention"
        print(f"  {label}: " + ", ".join(summary["leaked_ids"]))
        print()


def count_unavailable(results):
    return sum(1 for r in results if r.get("judge_verdict") == UNAVAILABLE)
