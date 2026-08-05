import pytest

from src.data_loader import load_train_samples
from src.detector import scan_workflow
from src.evaluate import load_untrusted_context_list

ENV_PROPAGATION_SAMPLE = "63dd94b83c0647426a8ca60b"
STEP_OUTPUT_SAMPLE = "63dd950d80aa29a6fd4877fb"
COMPOSITE_INPUT_SAMPLE = "63dd95c080aa29a6fd48843c"
RUN_PARSING_SAMPLE = "63dd950c80aa29a6fd4877e2"
FALSE_POSITIVE_SAMPLE = "63c49aca6fc19abdf9cb86f4"
FN_COMPOUND_HEAD_REF = "63dd95bc80aa29a6fd48841a"
FN_COMMITS_MESSAGE = "63dd95c880aa29a6fd4884a1"


@pytest.mark.usefixtures("require_dataset")
def test_env_propagation_sample_detected() -> None:
    sample = next(s for s in load_train_samples() if s.sample_id == ENV_PROPAGATION_SAMPLE)
    findings = scan_workflow(sample.workflow_path, load_untrusted_context_list())
    assert len(findings) > 0


@pytest.mark.usefixtures("require_dataset")
def test_step_output_sample_detected() -> None:
    sample = next(s for s in load_train_samples() if s.sample_id == STEP_OUTPUT_SAMPLE)
    findings = scan_workflow(sample.workflow_path, load_untrusted_context_list())
    assert len(findings) > 0


@pytest.mark.usefixtures("require_dataset")
def test_composite_input_default_sample_detected() -> None:
    sample = next(s for s in load_train_samples() if s.sample_id == COMPOSITE_INPUT_SAMPLE)
    findings = scan_workflow(sample.workflow_path, load_untrusted_context_list())
    assert len(findings) > 0


@pytest.mark.usefixtures("require_dataset")
def test_run_parsing_sample_detected() -> None:
    sample = next(s for s in load_train_samples() if s.sample_id == RUN_PARSING_SAMPLE)
    findings = scan_workflow(sample.workflow_path, load_untrusted_context_list())
    assert len(findings) > 0


@pytest.mark.usefixtures("require_dataset")
def test_clean_sample_with_with_passed_branch_stays_clean() -> None:
    sample = next(s for s in load_train_samples() if s.sample_id == FALSE_POSITIVE_SAMPLE)
    findings = scan_workflow(sample.workflow_path, load_untrusted_context_list())
    assert len(findings) == 0


@pytest.mark.usefixtures("require_dataset")
def test_compound_head_ref_in_composite_action_detected() -> None:
    sample = next(s for s in load_train_samples() if s.sample_id == FN_COMPOUND_HEAD_REF)
    findings = scan_workflow(sample.workflow_path, load_untrusted_context_list())
    assert len(findings) > 0


@pytest.mark.usefixtures("require_dataset")
def test_commits_message_input_flow_detected() -> None:
    sample = next(s for s in load_train_samples() if s.sample_id == FN_COMMITS_MESSAGE)
    findings = scan_workflow(sample.workflow_path, load_untrusted_context_list())
    assert len(findings) > 0
