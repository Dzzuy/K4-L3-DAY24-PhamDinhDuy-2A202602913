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
CLASSIFICATIONS = frozenset({"public", "internal", "restricted"})


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
    """Decide a tool call before execution, using the lab's principal fixture."""
    if context.data_classification not in CLASSIFICATIONS:
        return False, "Phân loại dữ liệu không hợp lệ"
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Dữ liệu restricted không được đi qua run có egress"
    if context.delegation_depth < 0:
        return False, "Độ sâu delegation không hợp lệ"

    try:
        principals = json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return False, f"Không đọc được danh sách principal: {type(exc).__name__}"
    if not isinstance(principals, dict):
        return False, "Danh sách principal không hợp lệ"

    principal = principals.get(context.principal_id)
    if not isinstance(principal, dict):
        return False, "Principal không có trong danh sách quyền"
    if context.request_purpose not in principal.get("purposes", ()):
        return False, "Mục đích xử lý không được phép cho principal"
    if not context.requested_tool:
        return False, "Thiếu tên tool cần gọi"
    if context.requested_tool not in principal.get("allowed_tools", ()):
        return False, "Principal không được phép gọi tool này"
    if context.requested_tool not in context.agent_scopes:
        return False, "Tool nằm ngoài phạm vi quyền của agent"
    if context.delegation_depth > 0 and context.requested_tool not in context.parent_scopes:
        return False, "Tool nằm ngoài phạm vi quyền của agent cha"

    try:
        expires_at = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return False, "Thời hạn run không hợp lệ"
    if expires_at.tzinfo is None or expires_at.utcoffset() != timedelta(0):
        return False, "Thời hạn run phải có múi giờ UTC"
    if expires_at <= datetime.now(timezone.utc):
        return False, "Thời hạn run đã hết"

    return True, "Principal, mục đích, phạm vi quyền và thời hạn đều hợp lệ"
