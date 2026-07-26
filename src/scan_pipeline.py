from pathlib import Path

from src.detector import Finding, scan_workflow
from src.llm import dedupe_findings, request_additional_findings


def collect_findings(
    workflow_path: Path,
    untrusted_contexts: list[str],
    use_llm: bool = False,
    llm_client=None,
) -> list[Finding]:
    rule_findings = scan_workflow(workflow_path, untrusted_contexts)
    if not use_llm:
        return rule_findings

    content = workflow_path.read_text(encoding="utf-8", errors="replace")
    llm_findings = request_additional_findings(
        workflow_path,
        content,
        untrusted_contexts,
        rule_findings,
        client=llm_client,
    )
    return dedupe_findings(rule_findings + llm_findings)
