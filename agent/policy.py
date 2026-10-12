"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
KNOWN_TOOLS = frozenset({"search_docs", "read_customer", "http_post"})


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    """Authorize one tool call using the trusted simulated principal fixture.

    Callers must check before executing the tool and record either outcome.
    Missing or malformed authorization inputs fail closed with an audit reason.
    """
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "restricted data must not leave a run with egress enabled"
    if (not isinstance(context.data_classification, str)
            or context.data_classification not in {"public", "internal", "restricted"}):
        return False, "unknown data classification"
    if not isinstance(context.egress_enabled, bool):
        return False, "egress capability must be an explicit boolean"
    if not context.agent_owner or not isinstance(context.agent_owner, str):
        return False, "missing agent identity"
    if (not isinstance(context.delegation_depth, int)
            or isinstance(context.delegation_depth, bool)
            or context.delegation_depth < 0):
        return False, "invalid delegation depth"

    if not isinstance(context.expires_at, str) or not context.expires_at:
        return False, "missing run expiry"
    try:
        expires_at = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
    except ValueError:
        return False, "invalid run expiry: expected ISO-8601 UTC"
    if expires_at.tzinfo is None or expires_at.utcoffset() != timedelta(0):
        return False, "run expiry must include the UTC timezone"
    if expires_at <= datetime.now(timezone.utc):
        return False, "run authorization has expired"

    if not isinstance(context.principal_id, str) or not context.principal_id:
        return False, "missing principal identity"
    try:
        principals = json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, "trusted principal fixture is unavailable or invalid"
    if not isinstance(principals, dict):
        return False, "trusted principal fixture must contain an identity mapping"
    principal = principals.get(context.principal_id)
    if not isinstance(principal, dict):
        return False, "unknown principal identity"

    allowed_tools = principal.get("allowed_tools")
    purposes = principal.get("purposes")
    if (not isinstance(allowed_tools, list)
            or not all(isinstance(tool, str) for tool in allowed_tools)
            or not isinstance(purposes, list)
            or not all(isinstance(purpose, str) for purpose in purposes)):
        return False, "principal authorization metadata is invalid"
    if not isinstance(context.request_purpose, str) or context.request_purpose not in purposes:
        return False, "request purpose is not authorized for this principal"
    if not isinstance(context.requested_tool, str) or context.requested_tool not in KNOWN_TOOLS:
        return False, "missing or unknown requested tool"

    if (not isinstance(context.agent_scopes, (tuple, list, set, frozenset))
            or not context.agent_scopes
            or not all(isinstance(tool, str) for tool in context.agent_scopes)):
        return False, "missing or invalid agent scopes"
    effective_scopes = set(allowed_tools).intersection(context.agent_scopes)
    if context.delegation_depth > 0:
        if (not isinstance(context.parent_scopes, (tuple, list, set, frozenset))
                or not context.parent_scopes
                or not all(isinstance(tool, str) for tool in context.parent_scopes)):
            return False, "delegated call requires valid parent scopes"
        effective_scopes.intersection_update(context.parent_scopes)
    if context.requested_tool not in effective_scopes:
        return False, "requested tool is outside the effective principal/agent/parent scopes"
    if context.requested_tool == "http_post" and not context.egress_enabled:
        return False, "network tool requires an egress-enabled run"

    return True, "principal, purpose, effective scopes and run expiry authorize this tool"
