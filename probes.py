"""
Phase 4 — The probe library loader.

The probes themselves now live in probes.json, so the library can grow
without touching code. This module loads them, validates the shape, and
offers a bit of filtering.

A probe looks like:

    {
      "id":           "P01",
      "category":     "instruction_override",
      "note":         "what this probe is actually testing",
      "text":         "the input sent to the bot",
      "context_file": "documents/acme_faq.txt"   # optional, Phase 5
    }

A probe with a context_file is an *indirect* test: the file is handed to the
bot as background material, and the hidden instruction lives in there rather
than in the user's message.
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
LIBRARY_PATH = os.path.join(HERE, "probes.json")
AGENT_LIBRARY_PATH = os.path.join(HERE, "agent_probes.json")

# Which probe library backs each target mode.
LIBRARY_FOR_MODE = {
    "disclosure": LIBRARY_PATH,
    "action": AGENT_LIBRARY_PATH,
}

REQUIRED_FIELDS = ("id", "category", "text")


class ProbeError(Exception):
    """Raised when the probe library is malformed."""


def load(path=LIBRARY_PATH):
    """Load and validate the probe library. Returns a list of probe dicts."""
    if not os.path.exists(path):
        raise ProbeError(f"probe library not found: {path}")

    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ProbeError(f"probes.json is not valid JSON: {exc}") from exc

    probes = data.get("probes")
    if not isinstance(probes, list) or not probes:
        raise ProbeError("probes.json must contain a non-empty 'probes' list")

    seen = set()
    for probe in probes:
        missing = [f for f in REQUIRED_FIELDS if not probe.get(f)]
        if missing:
            raise ProbeError(
                f"probe {probe.get('id', '?')} is missing: {', '.join(missing)}"
            )
        if probe["id"] in seen:
            raise ProbeError(f"duplicate probe id: {probe['id']}")
        seen.add(probe["id"])

        probe.setdefault("note", "")
        probe.setdefault("context_file", None)

    return probes


def select(probes, categories=None, ids=None, skip_indirect=False):
    """
    Narrow a probe list.

    categories     keep only these categories
    ids            keep only these probe ids
    skip_indirect  drop probes that need a context document
    """
    chosen = probes

    if categories:
        wanted = {c.lower() for c in categories}
        chosen = [p for p in chosen if p["category"].lower() in wanted]

    if ids:
        wanted = {i.upper() for i in ids}
        chosen = [p for p in chosen if p["id"].upper() in wanted]

    if skip_indirect:
        chosen = [p for p in chosen if not p["context_file"]]

    return chosen


def categories(probes):
    """Every category present, in first-seen order."""
    ordered = []
    for probe in probes:
        if probe["category"] not in ordered:
            ordered.append(probe["category"])
    return ordered


def by_category(probes):
    """Group probes into {category: [probe, ...]}."""
    groups = {}
    for probe in probes:
        groups.setdefault(probe["category"], []).append(probe)
    return groups


def load_context(probe, base_dir=HERE):
    """Read the context document for an indirect probe, if it has one."""
    if not probe.get("context_file"):
        return None

    path = os.path.join(base_dir, probe["context_file"])
    if not os.path.exists(path):
        raise ProbeError(
            f"probe {probe['id']} references a missing file: {probe['context_file']}"
        )

    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


if __name__ == "__main__":
    library = load()
    groups = by_category(library)

    print(f"{len(library)} probes across {len(groups)} categories\n")
    for category, items in groups.items():
        print(f"  {category}  ({len(items)})")
        for probe in items:
            tag = "  [indirect]" if probe["context_file"] else ""
            print(f"    {probe['id']}  {probe['note']}{tag}")
        print()
