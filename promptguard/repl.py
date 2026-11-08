"""
promptguard.repl
================
Interactive REPL for PromptGuard — a persistent session so you can run
analyze / sanitize / defend / batch repeatedly without re-invoking the
command each time.

Launch with::

    promptguard --cli
    promptguard cli

Commands inside the session::

    a|analyze <text>        detect prompt injection in <text>
    s|sanitize <text>       strip attacker-controlled tokens from <text>
    d|defend <user-text>    build a hardened prompt (uses the current system
                            prompt; set it with `system`)
    system <prompt>         set the system prompt used by `defend`
    batch <file>            analyze each non-empty line of <file> and print
                            a summary table
    json                    toggle JSON output for analyze / batch
    help|?                  show this list
    quit|exit|q             leave the REPL

The REPL keeps the trained model loaded for the whole session, so repeated
analyze calls are fast. Ctrl-D / Ctrl-C exits cleanly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from . import Detector, __version__, build_defense, format_result, sanitize

HELP = """\
Commands:
  a|analyze <text>        detect prompt injection
  s|sanitize <text>       strip attacker-controlled tokens
  d|defend <user-text>    build a hardened prompt (uses current system prompt)
  system <prompt>         set the system prompt for `defend`
  batch <file>            analyze each line of <file>, print a summary table
  json                    toggle JSON output for analyze / batch
  help|?                  show this help
  quit|exit|q             exit the REPL
"""


def _cmd_analyze(detector: Detector, text: str, json_mode: bool) -> None:
    r = detector.analyze(text)
    if json_mode:
        print(json.dumps({
            "score": r.score, "level": r.level, "is_injection": r.is_injection,
            "heuristic_score": r.heuristic_score, "stat_anomaly_score": r.stat_anomaly_score,
            "ml_score": r.ml_score, "ml_available": r.ml_available,
            "matched": [{"sid": m.sid, "name": m.name, "severity": m.severity,
                         "weight": m.weight, "snippet": m.snippet} for m in r.matched],
            "features": r.features,
        }, indent=2))
    else:
        print(format_result(r, text))


def _cmd_sanitize(text: str) -> None:
    res = sanitize(text)
    print("Actions:")
    for a in res.actions:
        print(f"  - {a}")
    if not res.actions:
        print("  (no changes — input was clean)")
    print("\nSanitised output:")
    print(res.sanitized)


def _cmd_defend(user: str, system: str) -> None:
    res = build_defense(system, user)
    print("Hardened prompt:")
    print(res.prompt)
    print("\nNotes:")
    for n in res.notes:
        print(f"  - {n}")


def _cmd_batch(detector: Detector, path: str, json_mode: bool) -> None:
    p = Path(path).expanduser()
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        print(f"could not read {path}: {e}")
        return
    inputs = [ln.strip() for ln in lines if ln.strip()]
    if not inputs:
        print(f"(no non-empty lines in {path})")
        return
    if json_mode:
        out = []
        for t in inputs:
            r = detector.analyze(t)
            out.append({"text": t, "score": r.score, "level": r.level,
                        "is_injection": r.is_injection})
        print(json.dumps(out, indent=2))
        return
    flagged = 0
    print(f"\n{'#':>3}  {'score':>5}  {'level':<8}  text")
    print("-" * 72)
    for i, t in enumerate(inputs, 1):
        r = detector.analyze(t)
        flagged += int(r.is_injection)
        preview = t if len(t) <= 40 else t[:37] + "..."
        print(f"{i:>3}  {r.score:>5}  {r.level:<8}  {preview}")
    print("-" * 72)
    print(f"{flagged}/{len(inputs)} flagged as injection.\n")


def run_repl() -> int:
    print(f"PromptGuard v{__version__} — interactive REPL. "
          "Type 'help' for commands, 'quit' to exit.")
    detector = Detector()  # model loaded once for the whole session
    system_prompt = "You are a helpful assistant."
    json_mode = False
    while True:
        try:
            line = input("promptguard> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        cmd = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            break
        if cmd in ("help", "?"):
            print(HELP)
            continue
        if cmd == "json":
            json_mode = not json_mode
            print(f"JSON output: {'on' if json_mode else 'off'}")
            continue
        if cmd == "system":
            if not rest:
                print(f"current system prompt: {system_prompt!r}")
            else:
                system_prompt = rest
                print("system prompt updated.")
            continue
        if cmd in ("a", "analyze"):
            if not rest:
                print("usage: analyze <text>")
                continue
            _cmd_analyze(detector, rest, json_mode)
        elif cmd in ("s", "sanitize"):
            if not rest:
                print("usage: sanitize <text>")
                continue
            _cmd_sanitize(rest)
        elif cmd in ("d", "defend"):
            if not rest:
                print("usage: defend <user-text>  (set system prompt with `system <prompt>`)")
                continue
            _cmd_defend(rest, system_prompt)
        elif cmd == "batch":
            if not rest:
                print("usage: batch <file>")
                continue
            _cmd_batch(detector, rest, json_mode)
        else:
            print(f"unknown command: {cmd!r} (type 'help')")
    print("bye.")
    return 0


if __name__ == "__main__":
    sys.exit(run_repl())
