import re
from dataclasses import dataclass, field

EXPRESSION_PATTERN = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")
GITHUB_ENV_WRITE_PATTERN = re.compile(
    r'echo\s+(?:"(?P<quoted>[^"]+)"|(?P<unquoted>\S+))\s*>>\s*\$GITHUB_ENV',
    re.IGNORECASE,
)


@dataclass
class TaintState:
    tainted_env: set[str] = field(default_factory=set)
    tainted_inputs: set[str] = field(default_factory=set)
    tainted_step_outputs: dict[str, set[str]] = field(default_factory=dict)

    def copy(self) -> "TaintState":
        return TaintState(
            tainted_env=set(self.tainted_env),
            tainted_inputs=set(self.tainted_inputs),
            tainted_step_outputs={
                step_id: set(outputs) for step_id, outputs in self.tainted_step_outputs.items()
            },
        )


def normalize_expr(expr: str) -> str:
    return ".".join(part.strip() for part in expr.strip().split(".") if part.strip())


def normalize_array_indices(expr: str) -> str:
    return re.sub(r"\[\d+\]", "[*]", expr.strip())


def _matches_untrusted_context(expr: str, context: str) -> bool:
    normalized = normalize_array_indices(normalize_expr(expr))
    ctx_norm = normalize_array_indices(normalize_expr(context))
    return normalized == ctx_norm or normalized.startswith(f"{ctx_norm}.")


def _expression_parts(expr: str) -> list[str]:
    parts = re.split(r"\|\||&&", expr)
    return [part.strip() for part in parts if part.strip()]


def normalize_input_name(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def _is_simple_github_ref(part: str) -> bool:
    cleaned = part.strip().strip("()")
    return bool(re.match(r"^github\.[\w.\[\]\*]+$", cleaned))


def is_untrusted_source(expr: str, untrusted_contexts: list[str]) -> bool:
    for context in untrusted_contexts:
        if _matches_untrusted_context(expr, context):
            return True

    if re.search(r"==|!=|fromJson\(|contains\(|startsWith\(|endsWith\(", expr):
        return False

    if "||" not in expr and "&&" not in expr:
        return False

    for part in _expression_parts(expr):
        cleaned = part.strip().strip("()")
        if not _is_simple_github_ref(cleaned):
            continue
        for context in untrusted_contexts:
            if _matches_untrusted_context(cleaned, context):
                return True
    return False


def expr_is_tainted_or_untrusted(expr: str, state: TaintState, untrusted_contexts: list[str]) -> bool:
    if is_untrusted_source(expr, untrusted_contexts):
        return True
    return is_tainted_expr(expr, state)


def is_tainted_expr(expr: str, state: TaintState) -> bool:
    normalized = normalize_expr(expr)
    if normalized.startswith("env."):
        var_name = normalized.split(".", 1)[1]
        return var_name in state.tainted_env
    if normalized.startswith("inputs."):
        input_name = normalize_input_name(normalized.split(".", 1)[1])
        return input_name in state.tainted_inputs
    if normalized.startswith("steps.") and ".outputs." in normalized:
        parts = normalized.split(".")
        if len(parts) >= 4 and parts[0] == "steps" and parts[2] == "outputs":
            step_id = parts[1]
            output_name = parts[3]
            outputs = state.tainted_step_outputs.get(step_id, set())
            return "*" in outputs or output_name in outputs
    return False


def apply_env_bindings(
    state: TaintState,
    env_map: dict | None,
    untrusted_contexts: list[str],
) -> None:
    if not isinstance(env_map, dict):
        return
    for var_name, raw_value in env_map.items():
        if not isinstance(raw_value, str):
            continue
        for match in EXPRESSION_PATTERN.finditer(raw_value):
            expression = match.group(1)
            if expr_is_tainted_or_untrusted(expression, state, untrusted_contexts):
                state.tainted_env.add(str(var_name))


def apply_with_bindings_to_inputs(
    with_map: dict | None,
    state: TaintState,
    untrusted_contexts: list[str],
) -> TaintState:
    input_state = TaintState(tainted_inputs=set(state.tainted_inputs))
    if not isinstance(with_map, dict):
        return input_state
    for key, raw_value in with_map.items():
        if not isinstance(raw_value, str):
            continue
        for match in EXPRESSION_PATTERN.finditer(raw_value):
            expression = match.group(1)
            if expr_is_tainted_or_untrusted(expression, state, untrusted_contexts):
                input_state.tainted_inputs.add(normalize_input_name(str(key)))
    return input_state


def apply_input_defaults(
    input_state: TaintState,
    inputs_spec: dict | None,
    untrusted_contexts: list[str],
) -> None:
    if not isinstance(inputs_spec, dict):
        return
    for key, spec in inputs_spec.items():
        if not isinstance(spec, dict):
            continue
        default = spec.get("default")
        if not isinstance(default, str):
            continue
        for match in EXPRESSION_PATTERN.finditer(default):
            expression = match.group(1)
            if is_untrusted_source(expression, untrusted_contexts):
                input_state.tainted_inputs.add(normalize_input_name(str(key)))


def with_map_has_taint(
    with_map: dict | None,
    state: TaintState,
    untrusted_contexts: list[str],
) -> bool:
    if not isinstance(with_map, dict):
        return False
    for raw_value in with_map.values():
        if not isinstance(raw_value, str):
            continue
        for match in EXPRESSION_PATTERN.finditer(raw_value):
            expression = match.group(1)
            if expr_is_tainted_or_untrusted(expression, state, untrusted_contexts):
                return True
    return False


def taint_all_step_outputs(state: TaintState, step_id: str) -> None:
    state.tainted_step_outputs.setdefault(step_id, set()).add("*")


def propagate_github_env_writes(
    run_text: str,
    state: TaintState,
    untrusted_contexts: list[str],
) -> None:
    if not isinstance(run_text, str):
        return
    for line in run_text.splitlines():
        if "$GITHUB_ENV" not in line:
            continue
        for match in GITHUB_ENV_WRITE_PATTERN.finditer(line):
            assignment = match.group("quoted") or match.group("unquoted") or ""
            if "=" not in assignment:
                continue
            var_name, _, value_part = assignment.partition("=")
            var_name = var_name.strip()
            for expr_match in EXPRESSION_PATTERN.finditer(line):
                expression = expr_match.group(1)
                if expr_is_tainted_or_untrusted(expression, state, untrusted_contexts):
                    state.tainted_env.add(var_name)
                    break
            else:
                if value_part and any(
                    expr_is_tainted_or_untrusted(expr, state, untrusted_contexts)
                    for expr in (m.group(1) for m in EXPRESSION_PATTERN.finditer(value_part))
                ):
                    state.tainted_env.add(var_name)
