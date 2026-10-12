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


# Email and explicit account labels take precedence over generic number formats.
# A 12-digit bank account must not also be counted as a CCCD; a 10-digit
# account starting with 0 must not also be counted as a phone number.
_EMAIL = re.compile(
    r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+"
    r"(?![\w-])",
    re.IGNORECASE,
)
_BANK_ACCOUNT = re.compile(
    r"(?<!\w)(?:STK|số[ \t]+tài[ \t]+khoản|so[ \t]+tai[ \t]+khoan"
    r"|bank[_ \t]+account|account[_ \t]+number)"
    r"[ \t]*[:=]?[ \t]*(?:là[ \t]+|la[ \t]+)?"
    r"(?P<value>[0-9]{8,16})(?!\w)",
    re.IGNORECASE,
)
_CCCD = re.compile(r"(?<!\w)[0-9]{12}(?!\w)")
_PHONE = re.compile(
    r"(?<![\w+])(?:0(?:[ \t.-]?[0-9]){9,10}"
    r"|\+84(?:[ \t.-]?[0-9]){9,10})(?!\w)",
)


def detect(text: str) -> list[dict]:
    """Recognize the four lab PII formats, preserving original text offsets.

    These are format recognizers, not checks that an identity, telephone or
    account actually exists. In particular, unlabelled arbitrary account
    numbers and personal names are outside this regex-only recognizer.
    """
    entities = []
    patterns = (
        ("EMAIL", _EMAIL, None),
        ("VN_BANK_ACCOUNT", _BANK_ACCOUNT, "value"),
        ("VN_CCCD", _CCCD, None),
        ("VN_PHONE", _PHONE, None),
    )
    for entity_type, pattern, group in patterns:
        for match in pattern.finditer(text):
            start, end = match.span(group) if group else match.span()
            if any(start < entity["end"] and entity["start"] < end
                   for entity in entities):
                continue
            entities.append({"type": entity_type, "start": start, "end": end})
    return sorted(entities, key=lambda entity: (entity["start"], entity["end"]))


def redact(text: str) -> str:
    """Replace complete detected spans without changing subsequent offsets."""
    for entity in reversed(detect(text)):
        text = (text[:entity["start"]] + f"[REDACTED_{entity['type']}]"
                + text[entity["end"]:])
    return text
