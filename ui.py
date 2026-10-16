#!/usr/bin/env python3
"""
A small local web dashboard for the harness — built for demoing on video.

Run it:
    python ui.py

then open http://127.0.0.1:8000 in a browser. Pick a target, click Run, and
watch each probe's verdict stream in live.

It uses only the Python standard library, serves on localhost only, and is a
thin shell over the same modules the command line uses — targets.py,
probes.py, runner.py, scorer.py, report.py. No new test logic lives here.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import probes as probe_lib
import runner
import targets as target_lib
from judge import available as judge_available
from scorer import summarize

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "ui.html")

HOST = "127.0.0.1"
PORT = int(os.environ.get("HARNESS_UI_PORT", "8000"))


def _resolve_judge(choice):
    """Mirror the CLI's judge resolution for the disclosure side."""
    if choice in (None, "", "off"):
        return None
    if choice == "mock":
        return "mock"
    if choice == "llm":
        return "ollama" if judge_available() else "mock"
    return "ollama" if judge_available() else "mock"  # auto


class Handler(BaseHTTPRequestHandler):
    # Quieter console — one line per request is enough during a demo.
    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))

    # -- helpers ------------------------------------------------------

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, content_type):
        try:
            with open(path, "rb") as handle:
                body = handle.read()
        except OSError:
            self.send_error(404, "not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Never let the browser cache the page — always serve the file on disk,
        # so an updated ui.html shows up on a plain refresh.
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _sse_event(self, event, data):
        """Write one Server-Sent Event and flush it, so the page sees it now.

        Returns False if the client has gone away (closed tab, navigated
        off), so the caller can stop cleanly instead of crashing.
        """
        payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        try:
            self.wfile.write(payload.encode("utf-8"))
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionError):
            return False

    # -- routing ------------------------------------------------------

    def do_GET(self):
        route = urlparse(self.path)
        path = route.path

        if path in ("/", "/index.html"):
            return self._send_file(PAGE, "text/html; charset=utf-8")

        if path == "/api/targets":
            return self._api_targets()

        if path == "/api/models":
            return self._api_models()

        if path == "/api/run-stream":
            return self._api_run_stream(parse_qs(route.query))

        self.send_error(404, "not found")

    # -- endpoints ----------------------------------------------------

    def _api_targets(self):
        try:
            config = target_lib.load_config()
        except target_lib.TargetError as exc:
            return self._send_json({"error": str(exc)}, status=500)

        out = []
        for name, entry in config.items():
            kind = entry.get("type")
            mode = {"agent": "action"}.get(kind, "disclosure")
            out.append({
                "name": name,
                "label": entry.get("label", name),
                "mode": mode,
                "authorized": bool(entry.get("authorized")),
            })
        return self._send_json({"targets": out})

    def _api_models(self):
        import target_bot
        models = target_bot.list_models()
        available = bool(models)
        # "default" lets the harness use its built-in default / mock fallback.
        return self._send_json({"models": models, "ollama": available})

    def _api_run_stream(self, query):
        name = (query.get("target") or ["local"])[0]
        judge_choice = (query.get("judge") or ["off"])[0]
        categories = query.get("category") or None
        save_report = (query.get("report") or ["0"])[0] == "1"
        model = (query.get("model") or [""])[0] or None

        try:
            target = target_lib.get(name)
        except target_lib.TargetError as exc:
            return self._send_json({"error": str(exc)}, status=400)

        try:
            library = probe_lib.load(probe_lib.LIBRARY_FOR_MODE[target.mode])
        except probe_lib.ProbeError as exc:
            return self._send_json({"error": str(exc)}, status=500)

        selected = probe_lib.select(library, categories=categories)

        judge_backend = None if target.mode == "action" \
            else _resolve_judge(judge_choice)

        # Open the event stream. Close the connection when the run ends so
        # every client gets a clean end-of-stream (the browser's EventSource
        # is told to stop by the page when the summary arrives).
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        self._sse_event("start", {
            "target": target.name,
            "label": target.describe(),
            "mode": target.mode,
            "judge": judge_backend or "off",
            "model": model or "default",
            "total": len(selected),
        })

        results = []
        try:
            for index, result in enumerate(
                runner.run_iter(target, selected=selected,
                                judge_backend=judge_backend, model=model),
                start=1,
            ):
                results.append(result)
                if not self._sse_event("result", {"index": index,
                                                  "result": result}):
                    return  # client disconnected; stop quietly
        except Exception as exc:  # keep the demo alive on a backend hiccup
            self._sse_event("error", {"message": str(exc)})
            return

        summary = summarize(results)
        report_path = None
        if save_report:
            try:
                import report as report_lib
                from datetime import datetime
                meta = {
                    "mode": target.mode,
                    "target_name": target.name,
                    "target_label": target.describe(),
                    "model": model or "default",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "scoring": ("action-log policy check"
                                if target.mode == "action"
                                else "string match" + (
                                    f" + {judge_backend} judge"
                                    if judge_backend else "")),
                    "judge_backend": judge_backend,
                    "authorization": f"target '{target.name}' marked authorized",
                }
                md_path, _ = report_lib.write(results, summary, meta)
                report_path = os.path.relpath(md_path, HERE)
            except Exception as exc:
                report_path = f"(report failed: {exc})"

        self._sse_event("summary", {
            "summary": summary,
            "mode": target.mode,
            "report_path": report_path,
        })


def main():
    if not os.path.exists(PAGE):
        print(f"error: {PAGE} is missing — keep ui.html next to ui.py.",
              file=sys.stderr)
        return 2

    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}"
    print("=" * 56)
    print("  FoolTheBot — web UI")
    print(f"  open:  {url}")
    print("  stop:  Ctrl-C")
    print("=" * 56)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
