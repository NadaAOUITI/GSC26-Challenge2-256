import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from src.detector import Finding, _line_for_expression, _rel_path
from src.taint import normalize_expr

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "google/gemma-2-9b-it:free"
JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


class OpenRouterError(RuntimeError):
    pass


class MissingApiKeyError(OpenRouterError):
    pass


@dataclass
class LlmFinding:
    file: str
    line: int
    expression: str
    explanation: str


def get_api_key() -> str:
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise MissingApiKeyError(
            "OPENROUTER_API_KEY is not set. Export it before using --use-llm."
        )
    return key


def get_model() -> str:
    return os.environ.get("OPENROUTER_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL


def extract_json_array(text: str) -> list[dict]:
    stripped = text.strip()
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass

    match = JSON_BLOCK_PATTERN.search(text)
    if match:
        parsed = json.loads(match.group(1).strip())
        if isinstance(parsed, list):
            return parsed

    start = stripped.find("[")
    end = stripped.rfind("]")
    if start >= 0 and end > start:
        parsed = json.loads(stripped[start : end + 1])
        if isinstance(parsed, list):
            return parsed

    raise OpenRouterError("LLM response did not contain a JSON array")


def build_detection_prompt(
    workflow_content: str,
    rel_path: str,
    untrusted_contexts: list[str],
    existing_findings: list[Finding],
) -> str:
    existing = [
        {
            "file": finding.rel_path or finding.file,
            "line": finding.line,
            "expression": finding.expression,
        }
        for finding in existing_findings
    ]
    untrusted_lines = "\n".join(f"- {item}" for item in untrusted_contexts)
    return f"""You analyze GitHub Actions workflows for shell command injection.

Untrusted GitHub contexts (direct use in run: blocks is dangerous):
{untrusted_lines}

Also flag tainted uses of env.*, inputs.*, or steps.*.outputs.* inside run: blocks when they can carry untrusted data.

Workflow file: {rel_path}

```yaml
{workflow_content}
```

Rule-based scanner already reported:
{json.dumps(existing, indent=2)}

Return ONLY a JSON array of ADDITIONAL vulnerabilities not already listed.
Each item must use keys: file, line, expression, explanation.
Use file path "{rel_path}" unless the sink is clearly in a referenced composite action path.
If there are no additional findings, return [].
"""


class OpenRouterClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        http_post=None,
    ) -> None:
        self.api_key = api_key or get_api_key()
        self.model = model or get_model()
        self._http_post = http_post or self._default_post

    @classmethod
    def from_env(cls, http_post=None) -> "OpenRouterClient":
        return cls(http_post=http_post)

    def _default_post(self, url: str, body: bytes, headers: dict[str, str]) -> dict:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise OpenRouterError(f"OpenRouter HTTP {error.code}: {detail}") from error
        except urllib.error.URLError as error:
            raise OpenRouterError(f"OpenRouter request failed: {error}") from error

    def chat(self, prompt: str, temperature: float = 0.0) -> str:
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a precise GitHub Actions security reviewer. "
                        "Respond with valid JSON only."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/NadaAOUITI/GSC26-Challenge2-256",
            "X-Title": "GSC26 Challenge 02",
        }
        response = self._http_post(
            OPENROUTER_URL,
            json.dumps(payload).encode("utf-8"),
            headers,
        )
        try:
            return response["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as error:
            raise OpenRouterError(f"Unexpected OpenRouter response shape: {response}") from error


def parse_llm_findings(raw: str) -> list[LlmFinding]:
    items = extract_json_array(raw)
    findings: list[LlmFinding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        expression = str(item.get("expression", "")).strip()
        if not expression:
            continue
        findings.append(
            LlmFinding(
                file=str(item.get("file", "")).strip(),
                line=int(item.get("line", 1) or 1),
                expression=expression,
                explanation=str(item.get("explanation", "LLM-reported injection sink.")).strip(),
            )
        )
    return findings


def llm_findings_to_domain(
    llm_findings: list[LlmFinding],
    workflow_path,
    workflow_content: str,
) -> list[Finding]:
    rel = _rel_path(workflow_path)
    domain: list[Finding] = []
    for item in llm_findings:
        file_path = item.file or rel
        line = item.line
        if line <= 1:
            line = _line_for_expression(workflow_content, item.expression, fallback=1)
        domain.append(
            Finding(
                file=str(workflow_path),
                line=line,
                expression=item.expression,
                context=normalize_expr(item.expression),
                explanation=item.explanation,
                propagated=False,
                rel_path=file_path if file_path.startswith("train/") else rel,
            )
        )
    return domain


def request_additional_findings(
    workflow_path,
    workflow_content: str,
    untrusted_contexts: list[str],
    existing_findings: list[Finding],
    client: OpenRouterClient | None = None,
) -> list[Finding]:
    client = client or OpenRouterClient.from_env()
    rel_path = _rel_path(workflow_path)
    prompt = build_detection_prompt(
        workflow_content,
        rel_path,
        untrusted_contexts,
        existing_findings,
    )
    raw = client.chat(prompt)
    parsed = parse_llm_findings(raw)
    return llm_findings_to_domain(parsed, workflow_path, workflow_content)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        rel = finding.rel_path or finding.file
        key = (rel, finding.line, normalize_expr(finding.expression))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
