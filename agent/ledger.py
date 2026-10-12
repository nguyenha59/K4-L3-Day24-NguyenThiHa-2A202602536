"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
        Chỉ kiểm tra file hiện có KHÔNG phát hiện được việc xoá dòng cuối
        hoặc viết lại cả file và tính lại chuỗi. Muốn phát hiện cắt đuôi
        phải lưu hash/số dòng cuối ở một nơi tin cậy bên ngoài file rồi
        đối chiếu. Bài lab không cung cấp mốc đó.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import threading


_GENESIS_HASH = "0" * 64
_HASH_FORMAT = re.compile(r"[0-9a-f]{64}")
_REQUIRED_FIELDS = (
    "ts", "agent_id", "run_id", "tool", "args_hash", "classification",
    "decision", "reason",
)
# Serialize callers within this process. The lab is single-process; this is
# not a cross-process lock or an external trusted checkpoint for the chain.
_LOCK = threading.RLock()


def _canonical(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False)


def _record_hash(record: dict) -> str:
    payload = {key: value for key, value in record.items() if key != "hash"}
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _unique_object(pairs: list[tuple]) -> dict:
    """Reject ambiguous JSON containing the same field more than once."""
    record = {}
    for key, value in pairs:
        if key in record:
            raise ValueError("duplicate ledger field")
        record[key] = value
    return record


def _read_records(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line, object_pairs_hook=_unique_object) for line in stream]


def _valid_chain(records: list[dict]) -> bool:
    previous = _GENESIS_HASH
    for record in records:
        if not isinstance(record, dict):
            return False
        if any(not isinstance(record.get(field), str) or not record[field].strip()
               for field in _REQUIRED_FIELDS):
            return False
        if record["decision"] not in {"allow", "deny"}:
            return False
        stored_hash = record.get("hash")
        if (not isinstance(stored_hash, str)
                or not _HASH_FORMAT.fullmatch(stored_hash)
                or record.get("prev_hash") != previous
                or stored_hash != _record_hash(record)):
            return False
        previous = stored_hash
    return True


def append(entry: dict, path: Path) -> dict:
    """Append metadata and argument hashes, never raw tool arguments or PII.

    The caller supplies metadata only (including OBO identity and TTL).
    Existing invalid chains are not extended. Empty reasons can be recorded
    for diagnosis, but verify() will reject them as required by the lab test.
    """
    if not isinstance(entry, dict):
        raise TypeError("ledger entry must be a dict")
    if any(field not in entry for field in _REQUIRED_FIELDS):
        raise ValueError("ledger entry is missing required metadata")
    # Copy and validate JSON before touching the file; do not mutate the caller.
    record = json.loads(_canonical(entry))
    path = Path(path)
    with _LOCK:
        if path.exists():
            try:
                records = _read_records(path)
                valid = _valid_chain(records)
            except (OSError, UnicodeError, ValueError, TypeError):
                raise ValueError("cannot append to an invalid ledger") from None
            if not valid:
                raise ValueError("cannot append to an invalid ledger")
        else:
            records = []
        record["prev_hash"] = records[-1]["hash"] if records else _GENESIS_HASH
        record["hash"] = _record_hash(record)
        path.parent.mkdir(parents=True, exist_ok=True)
        separator = ""
        if records:
            with path.open("rb") as existing:
                existing.seek(-1, 2)
                if existing.read(1) != b"\n":
                    separator = "\n"
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(separator + _canonical(record) + "\n")
    return record


def verify(path: Path) -> bool:
    """Check present records; tail deletion/full rehash need an external anchor."""
    with _LOCK:
        try:
            return _valid_chain(_read_records(Path(path)))
        except (OSError, UnicodeError, ValueError, TypeError):
            return False
