import json

import pytest

from src.detector import Finding
from src.llm import (
    MissingApiKeyError,
    OpenRouterClient,
    build_detection_prompt,
    dedupe_findings,
    extract_json_array,
    get_api_key,
    parse_llm_findings,
    request_additional_findings,
)
from src.taint import normalize_expr


def test_extract_json_array_from_fence() -> None:
    raw = 'Here you go:\n```json\n[{"expression": "github.head_ref"}]\n```'
    items = extract_json_array(raw)
    assert len(items) == 1
    assert items[0]["expression"] == "github.head_ref"


def test_parse_llm_findings_skips_invalid_items() -> None:
    raw = json.dumps(
        [
            {"file": "train/workflows/x.yml", "line": 3, "expression": "github.head_ref", "explanation": "x"},
            {"line": 4},
            "bad",
        ]
    )
    findings = parse_llm_findings(raw)
    assert len(findings) == 1
    assert findings[0].expression == "github.head_ref"


def test_dedupe_findings_by_expression() -> None:
    first = Finding(
        file="f",
        line=1,
        expression="github.head_ref",
        context="github.head_ref",
        explanation="a",
        rel_path="train/workflows/x.yml",
    )
    second = Finding(
        file="f",
        line=1,
        expression=" github.head_ref ",
        context="github.head_ref",
        explanation="b",
        rel_path="train/workflows/x.yml",
    )
    merged = dedupe_findings([first, second])
    assert len(merged) == 1
    assert normalize_expr(merged[0].expression) == "github.head_ref"


def test_build_detection_prompt_includes_untrusted_and_existing() -> None:
    prompt = build_detection_prompt(
        "run: echo",
        "train/workflows/x.yml",
        ["github.head_ref"],
        [],
    )
    assert "github.head_ref" in prompt
    assert "train/workflows/x.yml" in prompt
    assert "run: echo" in prompt


def test_missing_api_key_raises() -> None:
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        with pytest.raises(MissingApiKeyError):
            get_api_key()


def test_openrouter_client_uses_injected_http_post() -> None:
    def fake_post(url, body, headers):
        assert "Authorization" in headers
        return {"choices": [{"message": {"content": "[]"}}]}

    client = OpenRouterClient(api_key="test-key", http_post=fake_post)
    assert client.chat("prompt") == "[]"


def test_request_additional_findings_parses_response(tmp_path) -> None:
    workflow = tmp_path / "sample.yml"
    workflow.write_text("run: echo ${{ github.head_ref }}\n", encoding="utf-8")

    def fake_post(url, body, headers):
        payload = json.dumps(
            [
                {
                    "file": "train/workflows/sample.yml",
                    "line": 1,
                    "expression": "github.head_ref",
                    "explanation": "LLM found sink",
                }
            ]
        )
        return {"choices": [{"message": {"content": payload}}]}

    client = OpenRouterClient(api_key="test-key", http_post=fake_post)
    findings = request_additional_findings(
        workflow,
        workflow.read_text(encoding="utf-8"),
        ["github.head_ref"],
        [],
        client=client,
    )
    assert len(findings) == 1
    assert findings[0].expression == "github.head_ref"
    assert "LLM" in findings[0].explanation
