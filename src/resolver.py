import re
from pathlib import Path

USES_PATTERN = re.compile(r"^([^@]+)@([0-9a-f]{12,40})$")


def _sha_prefix(full_sha: str) -> str:
    return full_sha[:12]


def parse_uses(uses_value: str) -> tuple[str, str, str] | None:
    match = USES_PATTERN.match(uses_value.strip())
    if not match:
        return None
    reference, sha = match.group(1), match.group(2)
    parts = reference.split("/")
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    subpath = "/".join(parts[2:]) if len(parts) > 2 else ""
    return owner, repo, subpath if subpath else ""


def resolve_action_path(
    uses_value: str,
    actions_root: Path,
) -> Path | None:
    parsed = parse_uses(uses_value)
    if parsed is None:
        return None

    owner, repo, subpath = parsed
    sha = USES_PATTERN.match(uses_value.strip()).group(2)
    base = actions_root / owner / repo / _sha_prefix(sha)
    if subpath:
        candidate = base / subpath / "action.yml"
    else:
        candidate = base / "action.yml"
    return candidate if candidate.exists() else None


def resolve_reusable_workflow_path(
    uses_value: str,
    reusable_root: Path,
) -> Path | None:
    parsed = parse_uses(uses_value)
    if parsed is None:
        return None

    owner, repo, subpath = parsed
    if not subpath:
        return None

    sha = USES_PATTERN.match(uses_value.strip()).group(2)
    candidate = reusable_root / owner / repo / _sha_prefix(sha) / subpath
    return candidate if candidate.exists() else None
