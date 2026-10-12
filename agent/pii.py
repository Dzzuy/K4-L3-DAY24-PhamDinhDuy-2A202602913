"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_BANK_ACCOUNT = re.compile(
    r"\b(?:STK|số\s+tài\s+khoản|so\s+tai\s+khoan)\b\s*[:#-]?\s*"
    r"(?P<value>\d{8,16})(?!\d)",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
_PHONE = re.compile(r"(?<!\d)0\d{9,10}(?!\d)")
_CCCD = re.compile(r"(?<!\d)\d{12}(?!\d)")


def _overlaps(start: int, end: int, entities: list[dict]) -> bool:
    return any(start < entity["end"] and entity["start"] < end for entity in entities)


def detect(text: str) -> list[dict]:
    """Return non-overlapping PII spans in the original text."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    entities: list[dict] = []
    patterns = (
        ("VN_BANK_ACCOUNT", _BANK_ACCOUNT, "value"),
        ("EMAIL", _EMAIL, 0),
        ("VN_PHONE", _PHONE, 0),
        ("VN_CCCD", _CCCD, 0),
    )
    for entity_type, pattern, group in patterns:
        for match in pattern.finditer(text):
            start, end = match.span(group)
            if not _overlaps(start, end, entities):
                entities.append({"type": entity_type, "start": start, "end": end})
    return sorted(entities, key=lambda entity: entity["start"])


def redact(text: str) -> str:
    """Replace detected spans without invalidating earlier offsets."""
    redacted = text
    for entity in reversed(detect(text)):
        redacted = (
            redacted[:entity["start"]]
            + f"[REDACTED_{entity['type']}]"
            + redacted[entity["end"]:]
        )
    return redacted
