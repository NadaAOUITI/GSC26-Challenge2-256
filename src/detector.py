import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from src.paths import (
    DATASET_DIR,
    TRAIN_ACTIONS,
    TRAIN_REUSABLE,
    VALIDATION_ACTIONS,
    VALIDATION_REUSABLE,
)
from src.resolver import resolve_action_path, resolve_reusable_workflow_path
from src.taint import (
    TaintState,
    apply_env_bindings,
    apply_input_defaults,
    apply_with_bindings_to_inputs,
    expr_is_tainted_or_untrusted,
    is_tainted_expr,
    is_untrusted_source,
    normalize_expr,
    propagate_github_env_writes,
    taint_all_step_outputs,
    with_map_has_taint,
)

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


@dataclass
class Finding:
    file: str
    line: int
    expression: str
    context: str
    explanation: str
    propagated: bool = False
    rel_path: str = ""


def _rel_path(file_path: Path) -> str:
    try:
        return file_path.resolve().relative_to(DATASET_DIR.resolve()).as_posix()
    except ValueError:
        return file_path.as_posix()


def _line_for_expression(content: str, expression: str, fallback: int = 1) -> int:
    needle = f"${{{{ {expression} }}}}"
    compact = f"${{{{ {expression.strip()} }}}}"
    for candidate in (needle, compact, expression):
        index = content.find(candidate)
        if index >= 0:
            return content.count("\n", 0, index) + 1
    return fallback


def _finding(
    file_path: Path,
    content: str,
    expression: str,
    propagated: bool,
    fallback_line: int = 1,
) -> Finding:
    context = normalize_expr(expression)
    if propagated:
        explanation = (
            f"Tainted `{context}` appears inside a `run:` shell block "
            f"(multi-step code injection)."
        )
    else:
        explanation = (
            f"Untrusted `{context}` appears inside a `run:` shell block "
            f"(possible code injection)."
        )
    return Finding(
        file=str(file_path.as_posix()),
        line=_line_for_expression(content, expression, fallback_line),
        expression=expression,
        context=context,
        explanation=explanation,
        propagated=propagated,
        rel_path=_rel_path(file_path),
    )


def _scan_run_text(
    file_path: Path,
    content: str,
    run_text: str,
    state: TaintState,
    untrusted_contexts: list[str],
    fallback_line: int = 1,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(run_text, str):
        return findings
    for match in EXPRESSION_PATTERN.finditer(run_text):
        expression = match.group(1)
        if is_untrusted_source(expression, untrusted_contexts):
            findings.append(_finding(file_path, content, expression, False, fallback_line))
        elif is_tainted_expr(expression, state):
            findings.append(_finding(file_path, content, expression, True, fallback_line))
    return findings


def _scan_steps(
    steps: list | None,
    file_path: Path,
    content: str,
    state: TaintState,
    untrusted_contexts: list[str],
    visited: set[Path],
    actions_root: Path,
    reusable_root: Path,
    job_env: dict | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(steps, list):
        return findings

    if isinstance(job_env, dict):
        apply_env_bindings(state, job_env, untrusted_contexts)

    for step in steps:
        if not isinstance(step, dict):
            continue

        apply_env_bindings(state, step.get("env"), untrusted_contexts)

        if "run" in step:
            run_text = step["run"]
            findings.extend(
                _scan_run_text(file_path, content, run_text, state, untrusted_contexts)
            )
            propagate_github_env_writes(run_text, state, untrusted_contexts)

        step_id = step.get("id")
        uses_value = step.get("uses")
        with_map = step.get("with")

        if isinstance(uses_value, str):
            if step_id and with_map_has_taint(with_map, state, untrusted_contexts):
                taint_all_step_outputs(state, str(step_id))

            action_path = resolve_action_path(uses_value, actions_root)
            if action_path:
                input_state = TaintState()
                findings.extend(
                    _scan_composite_action(
                        action_path,
                        input_state,
                        untrusted_contexts,
                        visited,
                        actions_root,
                        reusable_root,
                    )
                )
                continue

            workflow_path = resolve_reusable_workflow_path(uses_value, reusable_root)
            if workflow_path:
                child_state = TaintState()
                apply_env_bindings(child_state, with_map, untrusted_contexts)
                input_state = apply_with_bindings_to_inputs(with_map, state, untrusted_contexts)
                for input_name in input_state.tainted_inputs:
                    child_state.tainted_inputs.add(input_name)
                findings.extend(
                    _scan_document(
                        workflow_path,
                        child_state,
                        untrusted_contexts,
                        visited,
                        actions_root,
                        reusable_root,
                    )
                )
    return findings


def _scan_composite_action(
    action_path: Path,
    input_state: TaintState,
    untrusted_contexts: list[str],
    visited: set[Path],
    actions_root: Path,
    reusable_root: Path,
) -> list[Finding]:
    resolved = action_path.resolve()
    if resolved in visited:
        return []
    visited.add(resolved)

    content = action_path.read_text(encoding="utf-8", errors="replace")
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError:
        return []

    if not isinstance(document, dict):
        return []

    state = input_state.copy()
    apply_input_defaults(state, document.get("inputs"), untrusted_contexts)

    runs = document.get("runs")
    if not isinstance(runs, dict):
        return []

    composite_steps = runs.get("steps")
    return _scan_steps(
        composite_steps,
        action_path,
        content,
        state,
        untrusted_contexts,
        visited,
        actions_root,
        reusable_root,
    )


def _scan_jobs(
    jobs: dict | None,
    file_path: Path,
    content: str,
    untrusted_contexts: list[str],
    visited: set[Path],
    actions_root: Path,
    reusable_root: Path,
    inherited_state: TaintState | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(jobs, dict):
        return findings

    for job in jobs.values():
        if not isinstance(job, dict):
            continue

        if isinstance(job.get("uses"), str):
            uses_value = job["uses"]
            with_map = job.get("with")
            workflow_path = resolve_reusable_workflow_path(uses_value, reusable_root)
            if workflow_path:
                child_state = inherited_state.copy() if inherited_state else TaintState()
                apply_env_bindings(child_state, with_map, untrusted_contexts)
                input_state = apply_with_bindings_to_inputs(
                    with_map, child_state, untrusted_contexts
                )
                for input_name in input_state.tainted_inputs:
                    child_state.tainted_inputs.add(input_name)
                findings.extend(
                    _scan_document(
                        workflow_path,
                        child_state,
                        untrusted_contexts,
                        visited,
                        actions_root,
                        reusable_root,
                    )
                )
            continue

        state = inherited_state.copy() if inherited_state else TaintState()
        findings.extend(
            _scan_steps(
                job.get("steps"),
                file_path,
                content,
                state,
                untrusted_contexts,
                visited,
                actions_root,
                reusable_root,
                job_env=job.get("env"),
            )
        )
    return findings


def _scan_document(
    file_path: Path,
    inherited_state: TaintState | None,
    untrusted_contexts: list[str],
    visited: set[Path],
    actions_root: Path,
    reusable_root: Path,
) -> list[Finding]:
    resolved = file_path.resolve()
    if resolved in visited:
        return []
    visited.add(resolved)

    content = file_path.read_text(encoding="utf-8", errors="replace")
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError:
        return _scan_run_text_fallback(file_path, content, untrusted_contexts)

    if not isinstance(document, dict):
        return []

    if "runs" in document and isinstance(document.get("runs"), dict):
        state = inherited_state.copy() if inherited_state else TaintState()
        apply_input_defaults(state, document.get("inputs"), untrusted_contexts)
        return _scan_steps(
            document["runs"].get("steps"),
            file_path,
            content,
            state,
            untrusted_contexts,
            visited,
            actions_root,
            reusable_root,
        )

    state = inherited_state.copy() if inherited_state else TaintState()
    file_env = document.get("env")
    if isinstance(file_env, dict):
        apply_env_bindings(state, file_env, untrusted_contexts)

    return _scan_jobs(
        document.get("jobs"),
        file_path,
        content,
        untrusted_contexts,
        visited,
        actions_root,
        reusable_root,
        inherited_state=state,
    )


def _scan_run_text_fallback(
    file_path: Path,
    content: str,
    untrusted_contexts: list[str],
) -> list[Finding]:
    state = TaintState()
    findings: list[Finding] = []
    run_pattern = re.compile(r"(?m)^(\s*)(?:-\s+)?run:\s*(?:\|\s*)?\n", re.MULTILINE)
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
                pos = line_end + 1
                continue
            if line.startswith(" " * (indent + 2)):
                lines.append(line[indent + 2 :] if len(line) > indent + 2 else "")
                pos = line_end + 1
                continue
            break
        run_text = "\n".join(lines)
        findings.extend(_scan_run_text(file_path, content, run_text, state, untrusted_contexts))
    return findings


def scan_file(
    file_path: Path,
    untrusted_contexts: list[str],
    visited: set[Path] | None = None,
    actions_root: Path | None = None,
    reusable_root: Path | None = None,
    inherited_state: TaintState | None = None,
    content: str | None = None,
) -> list[Finding]:
    if content is None and not file_path.exists():
        return []

    if visited is None:
        visited = set()

    actions_root = actions_root or TRAIN_ACTIONS
    reusable_root = reusable_root or actions_root.parent / "reusable_workflows"

    if content is None:
        return _scan_document(
            file_path,
            inherited_state,
            untrusted_contexts,
            visited,
            actions_root,
            reusable_root,
        )
    return _scan_document_content(
        file_path,
        content,
        inherited_state,
        untrusted_contexts,
        visited,
        actions_root,
        reusable_root,
    )


def _scan_document_content(
    file_path: Path,
    content: str,
    inherited_state: TaintState | None,
    untrusted_contexts: list[str],
    visited: set[Path],
    actions_root: Path,
    reusable_root: Path,
) -> list[Finding]:
    resolved = file_path.resolve()
    if resolved in visited:
        return []
    visited.add(resolved)

    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError:
        return _scan_run_text_fallback(file_path, content, untrusted_contexts)

    if not isinstance(document, dict):
        return []

    if "runs" in document and isinstance(document.get("runs"), dict):
        state = inherited_state.copy() if inherited_state else TaintState()
        apply_input_defaults(state, document.get("inputs"), untrusted_contexts)
        return _scan_steps(
            document["runs"].get("steps"),
            file_path,
            content,
            state,
            untrusted_contexts,
            visited,
            actions_root,
            reusable_root,
        )

    state = inherited_state.copy() if inherited_state else TaintState()
    file_env = document.get("env")
    if isinstance(file_env, dict):
        apply_env_bindings(state, file_env, untrusted_contexts)

    return _scan_jobs(
        document.get("jobs"),
        file_path,
        content,
        untrusted_contexts,
        visited,
        actions_root,
        reusable_root,
        inherited_state=state,
    )


def _artifact_roots_for(file_path: Path) -> tuple[Path, Path]:
    try:
        rel = file_path.resolve().relative_to(DATASET_DIR.resolve())
        if rel.parts and rel.parts[0] == "validation":
            return VALIDATION_ACTIONS, VALIDATION_REUSABLE
    except ValueError:
        pass
    return TRAIN_ACTIONS, TRAIN_REUSABLE


def scan_workflow(workflow_path: Path, untrusted_contexts: list[str]) -> list[Finding]:
    actions_root, reusable_root = _artifact_roots_for(workflow_path)
    findings = scan_file(
        workflow_path,
        untrusted_contexts,
        actions_root=actions_root,
        reusable_root=reusable_root,
    )
    return _dedupe_findings(findings)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.file, finding.line, finding.expression)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
