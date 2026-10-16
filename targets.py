"""
Phase 8 — Configurable targets.

Up to now the harness only knew how to talk to the built-in practice bot.
This module lets the target be any chat endpoint, described in targets.json,
so the same probe library can be run against a real application.

AUTHORIZATION
-------------
Every target carries an `authorized` flag, and the harness refuses to run
against a target where it is false. This is a deliberate speed bump, not a
security control: it exists so that pointing the tool at something takes a
conscious edit rather than a typo. Only ever set it true for a system you
own or have explicit written permission to test.

A target definition looks like:

    {
      "type": "http",
      "url": "https://example.com/chat",
      "method": "POST",
      "headers": {"Content-Type": "application/json"},
      "body": {"message": "{{PROBE}}"},
      "reply_path": "choices.0.message.content",
      "secret": "the value this bot should protect",
      "authorized": true
    }

{{PROBE}} is replaced with the probe text anywhere it appears in the body.
{{CONTEXT}} is replaced with the document text for indirect probes.
reply_path is a dotted path into the response JSON; list indices are numbers.
Header values may use ${ENV_VAR} to pull a key from the environment rather
than hard-coding a credential in the file.
"""

import copy
import json
import os
import re
import urllib.request

import target_bot

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "targets.json")

REQUEST_TIMEOUT = 60


class TargetError(Exception):
    """Raised for a malformed, missing, or unauthorized target."""


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _substitute(value, probe_text, context_text):
    """Walk a nested structure replacing the {{PROBE}}/{{CONTEXT}} markers."""
    if isinstance(value, str):
        return (value
                .replace("{{PROBE}}", probe_text)
                .replace("{{CONTEXT}}", context_text or ""))
    if isinstance(value, dict):
        return {k: _substitute(v, probe_text, context_text)
                for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, probe_text, context_text) for v in value]
    return value


def _expand_env(value):
    """Replace ${VAR} in a string with the environment variable's value."""
    def swap(match):
        name = match.group(1)
        resolved = os.environ.get(name)
        if resolved is None:
            raise TargetError(
                f"target needs environment variable {name}, which is not set"
            )
        return resolved

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", swap, value)


def _dig(data, path):
    """Follow a dotted path into nested JSON. 'a.0.b' -> data['a'][0]['b']."""
    current = data
    for part in path.split("."):
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError) as exc:
                raise TargetError(
                    f"reply_path '{path}' does not fit the response shape"
                ) from exc
        elif isinstance(current, dict):
            if part not in current:
                raise TargetError(
                    f"reply_path '{path}' missing key '{part}' in response"
                )
            current = current[part]
        else:
            raise TargetError(f"reply_path '{path}' went past a leaf value")
    return current


# ----------------------------------------------------------------------
# Target types
# ----------------------------------------------------------------------

class BuiltinTarget:
    """The local practice bot from Phase 1. A talking target: scored on what
    it says."""

    type = "builtin"
    mode = "disclosure"

    def __init__(self, name, config):
        self.name = name
        self.label = config.get("label", name)
        self.secret = config.get("secret") or target_bot.SECRET
        self.hardened = bool(config.get("hardened"))
        self.backend = None

    def describe(self):
        tag = " + defenses" if self.hardened else ""
        return f"{self.label} [backend: {target_bot.active_backend()}{tag}]"

    def send(self, probe_text, context=None, model=None):
        return target_bot.send_message(
            probe_text, context=context, backend=self.backend,
            hardened=self.hardened, model=model,
        )

    def run_probe(self, probe_text, context=None, model=None):
        return {"reply": self.send(probe_text, context=context, model=model),
                "actions": []}


class HttpTarget:
    """Any chat endpoint reachable over HTTP. A talking target."""

    type = "http"
    mode = "disclosure"

    def __init__(self, name, config):
        self.name = name
        self.label = config.get("label", name)
        self.config = config

        for field in ("url", "body", "reply_path"):
            if not config.get(field):
                raise TargetError(f"target '{name}' is missing '{field}'")

        self.secret = config.get("secret")
        if not self.secret:
            raise TargetError(f"target '{name}' must define 'secret'")

    def describe(self):
        return f"{self.label} [{self.config['url']}]"

    def send(self, probe_text, context=None):
        config = self.config

        body = _substitute(copy.deepcopy(config["body"]), probe_text, context)
        headers = {k: _expand_env(v)
                   for k, v in config.get("headers", {}).items()}

        request = urllib.request.Request(
            config["url"],
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method=config.get("method", "POST"),
        )

        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except TargetError:
            raise
        except Exception as exc:
            return f"[target error: {exc}]"

        try:
            return str(_dig(payload, config["reply_path"])).strip()
        except TargetError as exc:
            return f"[target error: {exc}]"

    def run_probe(self, probe_text, context=None, model=None):
        return {"reply": self.send(probe_text, context=context), "actions": []}


class AgentTarget:
    """The vulnerable agent. An acting target: scored on what it *does*, by
    checking the action log against policy.py — not on what it says."""

    type = "agent"
    mode = "action"

    def __init__(self, name, config):
        import agent  # local import so the disclosure side never loads it
        self._agent = agent
        self.name = name
        self.label = config.get("label", name)
        self.secret = agent.SECRET
        self.hardened = bool(config.get("hardened"))
        self.backend = None

    def describe(self):
        tag = " + defenses" if self.hardened else ""
        return f"{self.label} [backend: {self._agent.active_backend()}{tag}]"

    def run_probe(self, probe_text, context=None, model=None):
        reply, actions = self._agent.run_task(
            probe_text, context=context, backend=self.backend,
            hardened=self.hardened, model=model,
        )
        return {"reply": reply, "actions": actions}


TYPES = {"builtin": BuiltinTarget, "http": HttpTarget, "agent": AgentTarget}


# ----------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------

def load_config(path=CONFIG_PATH):
    """Read targets.json."""
    if not os.path.exists(path):
        raise TargetError(f"target config not found: {path}")

    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise TargetError(f"targets.json is not valid JSON: {exc}") from exc

    targets = data.get("targets")
    if not isinstance(targets, dict) or not targets:
        raise TargetError("targets.json must contain a 'targets' object")

    return targets


def names(path=CONFIG_PATH):
    """Every target name defined in the config."""
    return list(load_config(path).keys())


def get(name="local", path=CONFIG_PATH, allow_unauthorized=False):
    """
    Build a target object by name.

    Refuses targets whose `authorized` flag is not true, unless explicitly
    overridden.
    """
    config = load_config(path)

    if name not in config:
        raise TargetError(
            f"no target named '{name}'. Available: {', '.join(config)}"
        )

    entry = config[name]
    kind = entry.get("type")

    if kind not in TYPES:
        raise TargetError(
            f"target '{name}' has unknown type '{kind}'. "
            f"Expected one of: {', '.join(TYPES)}"
        )

    if not entry.get("authorized") and not allow_unauthorized:
        raise TargetError(
            f"target '{name}' is not marked authorized.\n"
            f"  Only test systems you own or have written permission to test.\n"
            f"  To proceed, set \"authorized\": true for '{name}' in targets.json."
        )

    return TYPES[kind](name, entry)


if __name__ == "__main__":
    config = load_config()
    print(f"{len(config)} targets defined:\n")
    for name, entry in config.items():
        flag = "authorized" if entry.get("authorized") else "NOT authorized"
        print(f"  {name:22} {entry.get('type'):8} {flag}")
        print(f"  {'':22} {entry.get('label', '')}\n")
