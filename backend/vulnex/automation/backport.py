"""Step 10: when an upstream patch does not apply, an AI model ports the failed hunks.

The model never edits files freely. It returns exact "find this text, put that text" edits
for the files that have a ``.rej``; each edit is checked (the text must be found exactly once)
before it is made, and the result is the working tree that then becomes the CVE patch.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .ai import Chat

MAX_ROUNDS = 3
FILE_LIMIT = 60_000  # characters of one source file sent to the model

SYSTEM = (
    "You are a senior Linux distribution engineer backporting an upstream security fix to an "
    "older release of a package. You are given the full upstream patch, and for each file where "
    "some hunks were rejected, the current file and the rejected hunks. Port the intent of each "
    "rejected hunk to the current code with the smallest change that fixes the vulnerability. "
    "Do not refactor and do not touch other code. Reply with JSON only, in this shape: "
    '{"edits":[{"file":"path/relative/to/source","old":"exact existing text","new":"replacement"}],'
    '"explanation":"2-4 sentences: how the code differs in this release and how the fix was adapted"}. '
    '"old" must appear exactly once in the file and must be copied exactly, including whitespace.'
)


@dataclass
class BackportResult:
    ok: bool
    explanation: str = ""
    problems: list[str] = field(default_factory=list)


def _json(text: str) -> dict:
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start : end + 1])


def _file_view(path: Path) -> str:
    body = path.read_text(errors="replace")
    return body if len(body) <= FILE_LIMIT else body[:FILE_LIMIT] + "\n... (file truncated)"


def _apply_edits(src: Path, edits: list[dict], allowed: set[str]) -> list[str]:
    """Make the edits that are safe; return what was wrong with the rest."""
    problems: list[str] = []
    pending: dict[str, str] = {}
    for edit in edits:
        name = str(edit.get("file", "")).strip().lstrip("./")
        if name not in allowed:
            problems.append(f"{name or '(no file)'}: only these files may be edited: {sorted(allowed)}")
            continue
        text = pending.get(name) or (src / name).read_text(errors="replace")
        old, new = edit.get("old", ""), edit.get("new", "")
        if not old or text.count(old) != 1:
            problems.append(f"{name}: 'old' text was found {text.count(old) if old else 0} times, it must be exactly once")
            continue
        pending[name] = text.replace(old, new, 1)
    if not problems:
        for name, text in pending.items():
            (src / name).write_text(text)
    return problems


def backport(src: Path, upstream_patch: str, rejects: list[Path], chat: Chat | None) -> BackportResult:
    if chat is None:
        return BackportResult(False, problems=["No AI model is configured (set VULNEX_AI_API_KEY or provide GITHUB_TOKEN)."])
    targets = {str(r.relative_to(src))[: -len(".rej")] for r in rejects}
    context = [f"## Upstream patch\n{upstream_patch[:40_000]}"]
    for reject in rejects:
        name = str(reject.relative_to(src))[: -len(".rej")]
        target = src / name
        context.append(
            f"## File: {name}\n```\n{_file_view(target) if target.exists() else '(file does not exist)'}\n```\n"
            f"### Rejected hunks for {name}\n```\n{reject.read_text(errors='replace')}\n```"
        )
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "\n\n".join(context)}]
    problems: list[str] = []
    for _ in range(MAX_ROUNDS):
        reply = chat(messages)
        try:
            data = _json(reply)
            edits = data["edits"]
        except (ValueError, KeyError, TypeError) as error:
            problems = [f"The model did not return valid JSON edits ({error})"]
        else:
            problems = _apply_edits(src, edits, targets)
            if not problems and edits:
                for reject in rejects:
                    reject.unlink(missing_ok=True)
                    Path(str(reject)[: -len(".rej")] + ".orig").unlink(missing_ok=True)
                return BackportResult(True, explanation=str(data.get("explanation", "")).strip())
            if not edits:
                problems = ["The model returned no edits"]
        messages += [
            {"role": "assistant", "content": reply},
            {"role": "user", "content": "That did not work:\n- " + "\n- ".join(problems) + "\nReturn corrected JSON only."},
        ]
    return BackportResult(False, problems=problems)
