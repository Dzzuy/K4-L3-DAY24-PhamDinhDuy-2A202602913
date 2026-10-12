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

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
TICKET_NAME = re.compile(r"^ticket-(\d+)\.md$")
RUN_LIFETIME = timedelta(minutes=5)


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _args_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _decide(
    *, tool: str, args: object, classification: str, purpose: str,
    agent_id: str, run_id: str, scopes: tuple[str, ...], principal_id: str,
    expires_at: str, ledger_path: Path, egress_enabled: bool = False,
) -> bool:
    context = PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=agent_id,
        delegation_depth=0,
        egress_enabled=egress_enabled,
        principal_id=principal_id,
        requested_tool=tool,
        agent_scopes=scopes,
        parent_scopes=(),
        expires_at=expires_at,
    )
    allowed, reason = check(context)
    ledger.append(
        {
            "ts": _utc_now().isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": tool,
            "args_hash": _args_hash(args),
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
        },
        ledger_path,
    )
    return allowed


def _run_a(
    message: str, llm, principal_id: str, expires_at: str, ledger_path: Path,
) -> tuple[list[dict], tuple[int, ...], bool]:
    agent_id = "lab24-agent/run-a"
    run_id = str(uuid4())
    if not _decide(
        tool="search_docs", args=message, classification="internal",
        purpose="summarize-tickets", agent_id=agent_id, run_id=run_id,
        scopes=("search_docs",), principal_id=principal_id,
        expires_at=expires_at, ledger_path=ledger_path,
    ):
        return [], (), False

    docs = tools.search_docs(message)
    ticket_ids: set[int] = set()
    for doc in docs:
        match = TICKET_NAME.fullmatch(doc["id"])
        if match:
            ticket_ids.add(int(match.group(1)))
    injected = llm.find_injection("\n\n".join(doc["text"] for doc in docs))
    safe_docs = [{**doc, "text": pii.redact(doc["text"])} for doc in docs]
    return safe_docs, tuple(sorted(ticket_ids)), injected is not None


def _run_b(
    ticket_ids: tuple[int, ...], principal_id: str, expires_at: str,
    ledger_path: Path,
) -> None:
    if not ticket_ids:
        return
    agent_id = "lab24-agent/run-b"
    run_id = str(uuid4())
    decision = dict(
        tool="read_customer", classification="restricted",
        purpose="support-reply", agent_id=agent_id, run_id=run_id,
        scopes=("read_customer",), principal_id=principal_id,
        expires_at=expires_at, ledger_path=ledger_path,
    )
    # The private store is not opened until the principal can read it.
    if not _decide(args={"related_tickets": ticket_ids}, **decision):
        return

    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    relevant = set(ticket_ids)
    customer_ids = sorted({
        record["customer_id"] for record in customers
        if relevant.intersection(record.get("related_tickets", ()))
    })
    for customer_id in customer_ids:
        if _decide(args=customer_id, **decision):
            tools.read_customer(customer_id)


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir is not None else DEFAULT_LEDGER_PATH
    expires_at = (_utc_now() + RUN_LIFETIME).isoformat()
    safe_docs, ticket_ids, has_injection = _run_a(
        message, llm, principal_id, expires_at, ledger_path,
    )
    _run_b(ticket_ids, principal_id, expires_at, ledger_path)
    if has_injection:
        _decide(
            tool="http_post", args={"target": "local-sink"},
            classification="restricted", purpose="support-reply",
            agent_id="lab24-agent/egress-gate", run_id=str(uuid4()),
            scopes=("http_post",), principal_id=principal_id,
            expires_at=expires_at, ledger_path=ledger_path,
            egress_enabled=True,
        )
    return llm.summarize(safe_docs)
