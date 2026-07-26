from src.taint import (
    TaintState,
    apply_env_bindings,
    apply_input_defaults,
    expr_is_tainted_or_untrusted,
    is_tainted_expr,
    propagate_github_env_writes,
    taint_all_step_outputs,
    with_map_has_taint,
)

UNTRUSTED = ["github.event.pull_request.head.ref", "github.head_ref"]


def test_env_binding_taints_env_var() -> None:
    state = TaintState()
    apply_env_bindings(
        state,
        {"REF_BRANCH": "${{ github.event.pull_request.head.ref }}"},
        UNTRUSTED,
    )
    assert "REF_BRANCH" in state.tainted_env
    assert is_tainted_expr("env.REF_BRANCH", state)


def test_tainted_env_detected_in_later_check() -> None:
    state = TaintState(tainted_env={"SOURCE_BRANCH"})
    assert is_tainted_expr("env.SOURCE_BRANCH", state)
    assert not is_tainted_expr("env.SAFE_BRANCH", state)


def test_step_output_taint() -> None:
    state = TaintState()
    taint_all_step_outputs(state, "extract_branch")
    assert is_tainted_expr("steps.extract_branch.outputs.replaced", state)


def test_github_env_write_propagation() -> None:
    state = TaintState(tainted_env={"REF_BRANCH"})
    run_text = 'echo "SOURCE_BRANCH=${{ env.REF_BRANCH }}" >> $GITHUB_ENV'
    propagate_github_env_writes(run_text, state, UNTRUSTED)
    assert "SOURCE_BRANCH" in state.tainted_env


def test_input_default_taints_composite_input() -> None:
    state = TaintState()
    apply_input_defaults(
        state,
        {"head_ref": {"default": "${{ github.head_ref }}"}},
        UNTRUSTED,
    )
    assert "head_ref" in state.tainted_inputs
    assert is_tainted_expr("inputs.head_ref", state)


def test_with_map_has_taint_from_untrusted() -> None:
    state = TaintState()
    assert with_map_has_taint(
        {"string": "${{ github.event.pull_request.head.ref }}"},
        state,
        UNTRUSTED,
    )


def test_expr_is_tainted_or_untrusted_source() -> None:
    state = TaintState()
    assert expr_is_tainted_or_untrusted("github.head_ref", state, UNTRUSTED)
    state.tainted_env.add("VAR")
    assert expr_is_tainted_or_untrusted("env.VAR", state, UNTRUSTED)
