"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from uuid import uuid4

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


_TICKET_FILE = re.compile(r"ticket-([0-9]+)(?:b)?\.md")
_PARENT_SCOPES = ("search_docs", "read_customer")


@dataclass(frozen=True)
class _Run:
    agent_id: str
    run_id: str
    parent_run_id: str
    principal_id: str
    audit_principal_id: str
    scopes: tuple[str, ...]
    expires_at: str
    ledger_path: Path


@dataclass(frozen=True)
class _SearchResult:
    ticket_ids: tuple[int, ...]
    answer: str
    egress_requested: bool


def _authorize(run: _Run, tool: str, args: dict, classification: str,
               purpose: str, *, egress: bool = False, event: str = "tool_call") -> bool:
    """Fail closed: a policy decision and durable audit precede execution."""
    context = policy.PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=run.agent_id,
        delegation_depth=1,
        egress_enabled=egress,
        principal_id=run.principal_id,
        requested_tool=tool,
        agent_scopes=run.scopes,
        parent_scopes=_PARENT_SCOPES,
        expires_at=run.expires_at,
    )
    allow, reason = policy.check(context)
    args_hash = hashlib.sha256(
        json.dumps(args, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
    ).hexdigest()
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": run.agent_id,
        "run_id": run.run_id,
        "parent_run_id": run.parent_run_id,
        "on_behalf_of": run.audit_principal_id,
        "expires_at": run.expires_at,
        "tool": tool,
        "args_hash": args_hash,
        "classification": classification,
        "decision": "allow" if allow else "deny",
        "reason": reason,
        "event": event,
        "purpose": purpose,
        "delegation_depth": 1,
        "agent_scopes": list(run.scopes),
        "parent_scopes": list(_PARENT_SCOPES),
    }, run.ledger_path)
    return allow


def _run_a(message: str, llm, run: _Run) -> _SearchResult:
    """Search/summarize untrusted documents; no private-store or network tools."""
    if not _authorize(run, "search_docs", {"query": message}, "internal", "summarize-tickets"):
        return _SearchResult((), "Không được phép tìm kiếm ticket với principal này.", False)
    docs = tools.search_docs(message)
    combined = "\n\n".join(doc["text"] for doc in docs)
    injection = llm.find_injection(combined)
    ticket_ids = set()
    safe_docs = []
    for doc in docs:
        match = _TICKET_FILE.fullmatch(doc["id"])
        if match:
            ticket_ids.add(int(match.group(1)))
        safe_docs.append({"id": doc["id"], "text": pii.redact(doc["text"])})
    # Record the boundary as an audit event, never its raw input or matched IDs.
    _authorize(run, "search_docs", {"ticket_ids": sorted(ticket_ids),
                                    "untrusted_instruction_detected": injection is not None},
               "internal", "summarize-tickets", event="sanitized_boundary")
    answer = pii.redact(llm.summarize(safe_docs))
    # No customer IDs, destination URLs, instructions or text enter Run B.
    return _SearchResult(tuple(sorted(ticket_ids)), answer, injection is not None)


def _run_b(ticket_ids: tuple[int, ...], run: _Run) -> None:
    """Accept only typed filename-derived IDs and resolve trusted associations."""
    if any(type(ticket_id) is not int or ticket_id < 0 for ticket_id in ticket_ids):
        raise ValueError("Run B requires nonnegative numeric ticket IDs")
    if not ticket_ids:
        return
    # Gate even metadata access: support_l1 must never load customer records.
    if not _authorize(run, "read_customer", {"ticket_ids": ticket_ids},
                      "restricted", "support-reply", event="mapping_authorization"):
        return
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    selected = set(ticket_ids)
    customer_ids = {
        record["customer_id"]
        for record in customers
        if selected.intersection(record.get("related_tickets", []))
    }
    # Discard private records used to resolve the trusted routing map.
    del customers
    for customer_id in sorted(customer_ids):
        if _authorize(run, "read_customer", {"customer_id": customer_id},
                      "restricted", "support-reply"):
            # Private data stays in Run B; it is never sent to the summarizer.
            tools.read_customer(customer_id)


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Two independently scoped children of one trusted simulated parent."""
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir is not None else DEFAULT_LEDGER_PATH
    parent_run_id = uuid4().hex
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    try:
        trusted_principals = json.loads(policy.PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        trusted_principals = {}
    if isinstance(trusted_principals, dict) and principal_id in trusted_principals:
        audit_principal_id = principal_id
    else:
        # Unknown --as input can itself contain PII. Keep only a correlation hash.
        audit_principal_id = "unknown:" + hashlib.sha256(principal_id.encode("utf-8")).hexdigest()

    def new_run(name: str, scopes: tuple[str, ...]) -> _Run:
        identity = uuid4().hex
        return _Run(f"lab24-agent/{name}/{identity}", identity, parent_run_id,
                    principal_id, audit_principal_id, scopes, expires_at, ledger_path)

    run_a = new_run("run-a", ("search_docs",))
    run_b = new_run("run-b", ("read_customer",))
    result = _run_a(message, llm, run_a)
    _run_b(result.ticket_ids, run_b)
    if result.egress_requested:
        # The dispatcher records the rejected intent with a fixed lab target.
        # Run B receives only numeric IDs, and exposes no records to this check.
        allowed = _authorize(run_b, "http_post", {
            "url": "http://127.0.0.1:10024/reconcile",
            "source": "untrusted_instruction",
        }, "restricted", "support-reply", egress=True)
        if allowed:
            raise RuntimeError("restricted egress was unexpectedly authorized")
    return result.answer
