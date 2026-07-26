import difflib
import re
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path

from ruamel.yaml import YAML

from src.detector import EXPRESSION_PATTERN, Finding
from src.taint import is_untrusted_source, normalize_expr, normalize_input_name

INTERPOLATION_TEMPLATE = "${{{{ {expr} }}}}"


@dataclass
class StepFix:
    env_var: str
    env_value: str | None = None
    replacements: list[tuple[str, str]] = field(default_factory=list)


def _interpolation(expr: str) -> str:
    return f"${{{{ {expr.strip()} }}}}"


def _env_var_name(expression: str, context: str) -> str:
    normalized = normalize_expr(expression)
    if normalized.startswith("env."):
        return normalized.split(".", 1)[1].upper()
    if normalized.startswith("steps.") and ".outputs." in normalized:
        output_name = normalized.split(".")[-1]
        return re.sub(r"[^A-Za-z0-9_]", "_", output_name).upper() or "STEP_OUTPUT"
    if normalized.startswith("inputs."):
        input_name = normalize_input_name(normalized.split(".", 1)[1])
        return f"INPUTS_{input_name.upper()}"
    parts = [part.upper() for part in context.split(".") if part not in {"github", "event"}]
    if not parts:
        parts = ["TAINTED_VALUE"]
    name = "_".join(parts)
    return re.sub(r"[^A-Z0-9_]", "_", name)[:40]


def plan_step_fixes(finding: Finding, untrusted_contexts: list[str]) -> StepFix | None:
    expression = finding.expression.strip()
    context = finding.context
    old_token = _interpolation(expression)

    if finding.propagated:
        normalized = normalize_expr(expression)
        if normalized.startswith("env."):
            var_name = normalized.split(".", 1)[1]
            return StepFix(
                env_var=var_name,
                replacements=[(old_token, f'"${var_name}"')],
            )
        env_var = _env_var_name(expression, context)
        return StepFix(
            env_var=env_var,
            env_value=old_token,
            replacements=[(old_token, f'"${env_var}"')],
        )

    if is_untrusted_source(expression, untrusted_contexts):
        env_var = _env_var_name(expression, context)
        return StepFix(
            env_var=env_var,
            env_value=old_token,
            replacements=[(old_token, f'"${env_var}"')],
        )
    return None


def _iter_step_lists(document: dict) -> list[list]:
    lists: list[list] = []
    runs = document.get("runs")
    if isinstance(runs, dict) and isinstance(runs.get("steps"), list):
        lists.append(runs["steps"])
    jobs = document.get("jobs")
    if isinstance(jobs, dict):
        for job in jobs.values():
            if isinstance(job, dict) and isinstance(job.get("steps"), list):
                lists.append(job["steps"])
    return lists


def _apply_fixes_to_steps(steps: list, fixes: list[StepFix]) -> bool:
    changed = False
    for step in steps:
        if not isinstance(step, dict) or "run" not in step:
            continue
        run_text = step.get("run")
        if not isinstance(run_text, str):
            continue

        step_changed = False
        for fix in fixes:
            if fix.env_value and fix.env_value in run_text:
                if not isinstance(step.get("env"), dict):
                    step["env"] = {}
                if fix.env_var not in step["env"]:
                    step["env"][fix.env_var] = fix.env_value
                for old, new in fix.replacements:
                    if old in run_text:
                        run_text = run_text.replace(old, new)
                        step_changed = True
            elif not fix.env_value:
                for old, new in fix.replacements:
                    if old in run_text:
                        run_text = run_text.replace(old, new)
                        step_changed = True

        if step_changed:
            step["run"] = run_text
            changed = True
    return changed


def patch_file_content(
    content: str,
    findings: list[Finding],
    untrusted_contexts: list[str],
) -> str:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    document = yaml.load(content)
    if not isinstance(document, dict):
        return content

    fixes = []
    for finding in findings:
        step_fix = plan_step_fixes(finding, untrusted_contexts)
        if step_fix:
            fixes.append(step_fix)
    if not fixes:
        return content

    changed = False
    for steps in _iter_step_lists(document):
        if _apply_fixes_to_steps(steps, fixes):
            changed = True

    if not changed:
        return content

    buffer = StringIO()
    yaml.dump(document, buffer)
    return buffer.getvalue()


def make_unified_diff(rel_path: str, old_content: str, new_content: str) -> str:
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    diff_lines = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
    )
    body = "".join(diff_lines)
    if not body.strip():
        return ""
    return f"diff --git a/{rel_path} b/{rel_path}\n{body}"


def patch_file(
    file_path: Path,
    findings: list[Finding],
    untrusted_contexts: list[str],
) -> tuple[str, str] | None:
    if not file_path.exists():
        return None
    old_content = file_path.read_text(encoding="utf-8", errors="replace")
    new_content = patch_file_content(old_content, findings, untrusted_contexts)
    if new_content == old_content:
        return None
    rel_path = findings[0].rel_path or file_path.name
    return rel_path, make_unified_diff(rel_path, old_content, new_content)


def generate_patch_for_sample(
    sample_id: str,
    findings: list[Finding],
    untrusted_contexts: list[str],
) -> str | None:
    if not findings:
        return None

    by_file: dict[str, list[Finding]] = {}
    for finding in findings:
        key = finding.file
        by_file.setdefault(key, []).append(finding)

    diff_parts: list[str] = []
    for file_key, file_findings in by_file.items():
        result = patch_file(Path(file_key), file_findings, untrusted_contexts)
        if result:
            _, diff_text = result
            if diff_text.strip():
                diff_parts.append(diff_text)

    if not diff_parts:
        return None
    return "".join(diff_parts)


def apply_patch_to_content(content: str, findings: list[Finding], untrusted_contexts: list[str]) -> str:
    return patch_file_content(content, findings, untrusted_contexts)
