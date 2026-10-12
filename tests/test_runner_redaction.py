"""A ticket's raw PII must not enter the summarizer context."""

from agent import tools
from agent.runner import handle


def test_runner_redacts_ticket_pii_before_summarizing(monkeypatch, tmp_path):
    ticket = {
        "id": "ticket-001.md",
        "text": "Ticket: liên hệ 0912345678 hoặc a@example.vn.",
    }
    monkeypatch.setattr(tools, "search_docs", lambda message: [ticket])

    class InspectingLLM:
        def find_injection(self, text):
            return None

        def summarize(self, docs):
            summary_input = docs[0]["text"]
            assert "0912345678" not in summary_input
            assert "a@example.vn" not in summary_input
            assert "[REDACTED_VN_PHONE]" in summary_input
            assert "[REDACTED_EMAIL]" in summary_input
            return "Đã tóm tắt ticket."

    assert handle("ticket", InspectingLLM(), log_dir=tmp_path) == "Đã tóm tắt ticket."
