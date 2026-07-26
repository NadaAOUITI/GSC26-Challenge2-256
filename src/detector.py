import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from src.paths import TRAIN_ACTIONS
from src.resolver import resolve_action_path, resolve_reusable_workflow_path

DEFAULT_UNTRUSTED_CONTEXTS = [
    "github.head_ref",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.head_commit.message",
    "github.event.workflow_run.head_branch",
]

EXPRESSION_PATTERN = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")
USES_LINE_PATTERN = re.compile(r"^\s*uses:\s*(.+?)\s*$")


@dataclass
class Finding:
    file: str
    line: int
    expression: str
    context: str
    explanation: str


def _normalize_context(expression: str) -> str:
    return ".".join(part.strip() for part in expression.split(".") if part.strip())


def _is_untrusted(expression: str, untrusted_contexts: list[str]) -> bool:
    normalized = _normalize_context(expression)
    for context in untrusted_contexts:
        if normalized == context or normalized.startswith(f"{context}."):
            return True
    return False


def _line_number_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _scan_run_block(
    file_path: Path,
    content: str,
    run_text: str,
    run_start: int,
    untrusted_contexts: list[str],
) -> list[Finding]:
    findings: list[Finding] = []
    base_line = _line_number_for_offset(content, run_start)
    lines = run_text.splitlines() or [run_text]
    for index, line in enumerate(lines, start=0):
        for match in EXPRESSION_PATTERN.finditer(line):
            expression = match.group(1)
            if _is_untrusted(expression, untrusted_contexts):
                findings.append(
                    Finding(
                        file=str(file_path.as_posix()),
                        line=base_line + index,
                        expression=expression,
                        context=_normalize_context(expression),
                        explanation=(
                            f"Untrusted `{_normalize_context(expression)}` appears "
                            f"inside a `run:` shell block (possible code injection)."
                        ),
                    )
                )
    return findings


def _extract_run_blocks(content: str) -> list[tuple[int, str]]:
    blocks: list[tuple[int, str]] = []
    run_pattern = re.compile(r"(?m)^(\s*)run:\s*(?:\|\s*)?\n", re.MULTILINE)
    for match in run_pattern.finditer(content):
        indent = len(match.group(1))
        start = match.end()
        lines: list[str] = []
        pos = start
        while pos < len(content):
            line_end = content.find("\n", pos)
            if line_end == -1:
                line_end = len(content)
            line = content[pos:line_end]
            if line.strip() == "":
                lines.append(line)
                pos = line_end + 1
                continue
            if line.startswith(" " * (indent + 2)) or line.strip() == "":
                lines.append(line[indent + 2 :] if len(line) > indent + 2 else "")
                pos = line_end + 1
                continue
            break
        blocks.append((start, "\n".join(lines)))
    return blocks


def _extract_uses_values(content: str) -> list[str]:
    values: list[str] = []
    for line in content.splitlines():
        match = USES_LINE_PATTERN.match(line)
        if match:
            values.append(match.group(1).strip().strip("'").strip('"'))
    return values


def _scan_file_content(
    file_path: Path,
    content: str,
    untrusted_contexts: list[str],
    visited: set[Path],
    actions_root: Path,
    reusable_root: Path,
) -> list[Finding]:
    findings: list[Finding] = []
    for run_start, run_text in _extract_run_blocks(content):
        findings.extend(
            _scan_run_block(file_path, content, run_text, run_start, untrusted_contexts)
        )

    for uses_value in _extract_uses_values(content):
        action_path = resolve_action_path(uses_value, actions_root)
        if action_path:
            findings.extend(
                scan_file(
                    action_path,
                    untrusted_contexts,
                    visited,
                    actions_root,
                    reusable_root,
                )
            )
            continue

        workflow_path = resolve_reusable_workflow_path(uses_value, reusable_root)
        if workflow_path:
            findings.extend(
                scan_file(
                    workflow_path,
                    untrusted_contexts,
                    visited,
                    actions_root,
                    reusable_root,
                )
            )
    return findings


def scan_file(
    file_path: Path,
    untrusted_contexts: list[str],
    visited: set[Path] | None = None,
    actions_root: Path | None = None,
    reusable_root: Path | None = None,
) -> list[Finding]:
    if not file_path.exists():
        return []

    resolved = file_path.resolve()
    if visited is None:
        visited = set()
    if resolved in visited:
        return []
    visited.add(resolved)

    actions_root = actions_root or TRAIN_ACTIONS
    reusable_root = reusable_root or actions_root.parent / "reusable_workflows"

    content = file_path.read_text(encoding="utf-8", errors="replace")
    return _scan_file_content(
        file_path,
        content,
        untrusted_contexts,
        visited,
        actions_root,
        reusable_root,
    )


def scan_workflow(workflow_path: Path, untrusted_contexts: list[str]) -> list[Finding]:
    return scan_file(workflow_path, untrusted_contexts)
