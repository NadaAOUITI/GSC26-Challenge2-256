from src.patcher import patch_file_content, plan_step_fixes
from src.detector import Finding


UNTRUSTED = ["github.head_ref"]


def test_plan_direct_untrusted_fix() -> None:
    finding = Finding(
        file="train/workflows/x.yml",
        line=10,
        expression="github.head_ref",
        context="github.head_ref",
        explanation="test",
        propagated=False,
        rel_path="train/workflows/x.yml",
    )
    fix = plan_step_fixes(finding, UNTRUSTED)
    assert fix is not None
    assert fix.env_var == "HEAD_REF"
    assert fix.env_value == "${{ github.head_ref }}"


def test_plan_env_propagation_fix() -> None:
    finding = Finding(
        file="train/workflows/x.yml",
        line=10,
        expression="env.REF_BRANCH",
        context="env.REF_BRANCH",
        explanation="test",
        propagated=True,
        rel_path="train/workflows/x.yml",
    )
    fix = plan_step_fixes(finding, UNTRUSTED)
    assert fix is not None
    assert fix.env_var == "REF_BRANCH"
    assert fix.env_value is None
    assert fix.replacements == [('${{ env.REF_BRANCH }}', '"$REF_BRANCH"')]


def test_patch_file_content_adds_env_wrap() -> None:
    content = """jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.head_ref }}"
"""
    finding = Finding(
        file="train/workflows/x.yml",
        line=5,
        expression="github.head_ref",
        context="github.head_ref",
        explanation="test",
        propagated=False,
        rel_path="train/workflows/x.yml",
    )
    patched = patch_file_content(content, [finding], UNTRUSTED)
    assert "HEAD_REF" in patched
    assert '"$HEAD_REF"' in patched
    assert "HEAD_REF: ${{ github.head_ref }}" in patched
