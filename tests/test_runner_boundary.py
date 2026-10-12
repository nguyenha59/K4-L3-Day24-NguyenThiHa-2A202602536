"""Security boundaries beyond the mandatory grading suite."""
import json

import pytest

from agent import ledger, runner, tools
from agent.llm import MockLLM


def test_unknown_identity_is_denied_without_logging_its_pii(tmp_path, monkeypatch):
    identity = "unknown.person@example.vn"
    monkeypatch.setattr(tools, "search_docs", lambda query: pytest.fail("unknown identity searched"))
    runner.handle("ticket", MockLLM(), log_dir=tmp_path, principal_id=identity)
    text = (tmp_path / "ledger.jsonl").read_text(encoding="utf-8")
    assert identity not in text
    entry = json.loads(text)
    assert entry["decision"] == "deny"
    assert entry["on_behalf_of"].startswith("unknown:")
    assert ledger.verify(tmp_path / "ledger.jsonl")


def test_audit_failure_stops_before_tool_execution(tmp_path, monkeypatch):
    def broken_audit(*args, **kwargs):
        raise OSError("audit unavailable")

    monkeypatch.setattr(ledger, "append", broken_audit)
    monkeypatch.setattr(tools, "search_docs", lambda query: pytest.fail("unaudited tool executed"))
    with pytest.raises(OSError, match="audit unavailable"):
        runner.handle("ticket", MockLLM(), log_dir=tmp_path)


def test_sensitive_document_fields_are_redacted_before_summarization(tmp_path, monkeypatch):
    raw_email = "synthetic.person@example.vn"
    raw_cccd = "123456789012"
    monkeypatch.setattr(tools, "search_docs", lambda query: [
        {"id": "ticket-001.md", "text": f"Email {raw_email}; CCCD {raw_cccd}"}
    ])

    class InspectLLM(MockLLM):
        def summarize(self, docs):
            assert raw_email not in docs[0]["text"]
            assert raw_cccd not in docs[0]["text"]
            return docs[0]["text"]

    answer = runner.handle("ticket", InspectLLM(), log_dir=tmp_path)
    assert raw_email not in answer and raw_cccd not in answer
    assert "[REDACTED_EMAIL]" in answer and "[REDACTED_VN_CCCD]" in answer
