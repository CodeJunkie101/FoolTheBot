#!/usr/bin/env python3
"""
Phase 9 + 10 — The command-line interface.

One entry point for the whole harness.

    python harness.py run                      run every probe
    python harness.py run --report             also write a report
    python harness.py run --category roleplay  run one category
    python harness.py run --judge mock         add the model-based judge
    python harness.py probes                   list the probe library
    python harness.py targets                  list configured targets

Phase 10 is the `--fail-under` flag, which turns the harness into a
regression test: it exits non-zero when the pass rate drops below a
threshold, so CI can block a change that weakens a bot's defenses.

Exit codes
    0  run completed and met the threshold
    1  pass rate fell below --fail-under
    2  configuration or runtime error
"""

import argparse
import sys
from datetime import datetime

import probes as probe_lib
import runner
import targets as target_lib
from judge import available as judge_available
from scorer import summarize

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2


# ----------------------------------------------------------------------
# run
# ----------------------------------------------------------------------

def _resolve_judge(choice):
    """Turn the --judge flag into a backend name, or None to skip."""
    if choice == "off":
        return None
    if choice == "mock":
        return "mock"
    if choice == "llm":
        if not judge_available():
            print("error: --judge llm needs a local model, and none is "
                  "reachable.\n       Start Ollama, or use --judge mock.",
                  file=sys.stderr)
            raise SystemExit(EXIT_ERROR)
        return "ollama"
    # auto
    return "ollama" if judge_available() else "mock"


def cmd_run(args):
    try:
        target = target_lib.get(
            args.target, allow_unauthorized=args.allow_unauthorized
        )
    except target_lib.TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    library_path = probe_lib.LIBRARY_FOR_MODE[target.mode]
    try:
        library = probe_lib.load(library_path)
    except probe_lib.ProbeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    selected = probe_lib.select(
        library,
        categories=args.category,
        ids=args.id,
        skip_indirect=args.skip_indirect,
    )

    if not selected:
        print("error: no probes matched that selection.\n"
              "       Run 'python harness.py probes' to see what is available.",
              file=sys.stderr)
        return EXIT_ERROR

    # The judge reads a reply for disclosure. An agent is scored on its
    # actions, so the judge does not apply there.
    if target.mode == "action":
        if args.judge != "off":
            print("note: --judge does not apply to an agent target; it is "
                  "scored on its actions by policy. Ignoring.\n")
        judge_backend = None
    else:
        judge_backend = _resolve_judge(args.judge)

    print()
    print("=" * runner.WIDTH)
    print("  LLM safety harness")
    print(f"  target   {target.describe()}")
    print(f"  mode     {target.mode}")
    if args.model:
        print(f"  model    {args.model}")
    print(f"  probes   {len(selected)} of {len(library)}")
    if target.mode != "action":
        print(f"  judge    {judge_backend or 'off'}")
    print("=" * runner.WIDTH)
    print()

    try:
        results = runner.run(
            target,
            selected=selected,
            judge_backend=judge_backend,
            delay=args.delay,
            quiet=args.quiet,
            verbose=args.verbose,
            model=args.model,
        )
    except probe_lib.ProbeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.quiet:
        print()

    summary = summarize(results)
    runner.print_summary(summary, target, judge_backend)

    stalled = runner.count_unavailable(results)
    if stalled:
        print(f"  note: the judge could not reach a verdict on {stalled} "
              f"reply(ies); those rest on string matching alone.")
        print()

    if args.report:
        import report as report_lib

        if target.mode == "action":
            scoring = "action-log policy check"
        else:
            scoring = "string match" + (
                f" + {judge_backend} judge" if judge_backend else ""
            )

        meta = {
            "mode": target.mode,
            "target_name": target.name,
            "target_label": target.describe(),
            "model": args.model or "default",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scoring": scoring,
            "judge_backend": judge_backend,
            "authorization": f"target '{target.name}' marked authorized in "
                             f"targets.json",
        }
        md_path, json_path = report_lib.write(results, summary, meta)
        print(f"  report   {md_path}")
        print(f"  raw      {json_path}")
        print()

    if args.fail_under is not None:
        threshold = args.fail_under
        actual = summary["pass_rate"]
        if actual < threshold:
            print(f"  FAILED threshold: pass rate {actual * 100:.0f}% is below "
                  f"the required {threshold * 100:.0f}%")
            print()
            return EXIT_THRESHOLD
        print(f"  threshold met: {actual * 100:.0f}% >= "
              f"{threshold * 100:.0f}%")
        print()

    return EXIT_OK


# ----------------------------------------------------------------------
# probes
# ----------------------------------------------------------------------

def cmd_probes(args):
    path = (probe_lib.AGENT_LIBRARY_PATH if args.agent
            else probe_lib.LIBRARY_PATH)
    try:
        library = probe_lib.load(path)
    except probe_lib.ProbeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    selected = probe_lib.select(library, categories=args.category)
    groups = probe_lib.by_category(selected)

    kind = "agent action" if args.agent else "disclosure"
    print()
    print(f"{len(selected)} {kind} probes across {len(groups)} categories")
    print()

    for category, items in groups.items():
        print(f"  {category}  ({len(items)})")
        for probe in items:
            tag = "  [indirect]" if probe["context_file"] else ""
            print(f"    {probe['id']:5} {probe['note']}{tag}")
        print()

    return EXIT_OK


# ----------------------------------------------------------------------
# targets
# ----------------------------------------------------------------------

def cmd_targets(args):
    try:
        config = target_lib.load_config()
    except target_lib.TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print()
    print(f"{len(config)} targets defined in targets.json")
    print()
    for name, entry in config.items():
        flag = "authorized" if entry.get("authorized") else "NOT authorized"
        print(f"  {name}")
        print(f"    type          {entry.get('type')}")
        print(f"    status        {flag}")
        print(f"    label         {entry.get('label', '')}")
        if entry.get("url"):
            print(f"    url           {entry['url']}")
        print()

    print("  Only set \"authorized\": true for a system you own or have")
    print("  explicit written permission to test.")
    print()

    return EXIT_OK


# ----------------------------------------------------------------------
# models
# ----------------------------------------------------------------------

def cmd_models(args):
    import target_bot
    models = target_bot.list_models()
    print()
    if not models:
        print("No Ollama models found (is Ollama running? run: ollama serve).")
        print("The harness will fall back to its built-in mock model.")
        print("Install models with, e.g.:  ollama pull llama3.2")
        print()
        return EXIT_OK
    print(f"{len(models)} model(s) installed in Ollama:")
    for m in models:
        print(f"  {m}")
    print()
    print("Use one with:  python harness.py run --target local --model <name>")
    print()
    return EXIT_OK


# ----------------------------------------------------------------------
# argument parsing
# ----------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="harness",
        description="A defensive test harness that measures how well an LLM "
                    "application resists prompt-injection inputs.",
        epilog="Run only against systems you own or are explicitly "
               "authorized to test.",
    )
    sub = parser.add_subparsers(dest="command")

    # run ---------------------------------------------------------
    run_cmd = sub.add_parser("run", help="run probes against a target")
    run_cmd.add_argument(
        "--target", default="local",
        help="target name from targets.json (default: local)",
    )
    run_cmd.add_argument(
        "--category", action="append",
        help="only run this category (repeatable)",
    )
    run_cmd.add_argument(
        "--id", action="append",
        help="only run this probe id (repeatable)",
    )
    run_cmd.add_argument(
        "--skip-indirect", action="store_true",
        help="skip probes that need a context document",
    )
    run_cmd.add_argument(
        "--judge", choices=["auto", "llm", "mock", "off"], default="off",
        help="model-based judge (default: off)",
    )
    run_cmd.add_argument(
        "--model", default=None,
        help="Ollama model to test (default: llama3.2). "
             "See 'harness.py models' for installed ones.",
    )
    run_cmd.add_argument(
        "--report", action="store_true",
        help="write a Markdown and JSON report to reports/",
    )
    run_cmd.add_argument(
        "--quiet", action="store_true",
        help="one line per probe instead of the full transcript",
    )
    run_cmd.add_argument(
        "--verbose", action="store_true",
        help="show the judge's reasoning in the transcript",
    )
    run_cmd.add_argument(
        "--delay", type=float, default=0.0,
        help="seconds to pause between probes",
    )
    run_cmd.add_argument(
        "--fail-under", type=float, default=None, metavar="RATE",
        help="exit non-zero if the pass rate falls below this (e.g. 0.9)",
    )
    run_cmd.add_argument(
        "--allow-unauthorized", action="store_true",
        help=argparse.SUPPRESS,
    )
    run_cmd.set_defaults(func=cmd_run)

    # probes ------------------------------------------------------
    probes_cmd = sub.add_parser("probes", help="list the probe library")
    probes_cmd.add_argument(
        "--category", action="append", help="filter by category",
    )
    probes_cmd.add_argument(
        "--agent", action="store_true",
        help="list the agent action probes instead of the disclosure probes",
    )
    probes_cmd.set_defaults(func=cmd_probes)

    # targets -----------------------------------------------------
    targets_cmd = sub.add_parser("targets", help="list configured targets")
    targets_cmd.set_defaults(func=cmd_targets)

    # models ------------------------------------------------------
    models_cmd = sub.add_parser("models", help="list installed Ollama models")
    models_cmd.set_defaults(func=cmd_models)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_OK

    if getattr(args, "fail_under", None) is not None:
        if not 0.0 <= args.fail_under <= 1.0:
            print("error: --fail-under takes a rate between 0 and 1 "
                  "(e.g. 0.9 for 90%)", file=sys.stderr)
            return EXIT_ERROR

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
