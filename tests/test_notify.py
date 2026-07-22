"""Tests for optional drift notification (R8)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from steward.cli import app
from steward.notify import (
    NotifyError,
    build_drift_payload,
    post_drift_notification,
)

runner = CliRunner()


def _reconciliation() -> SimpleNamespace:
    return SimpleNamespace(
        source_name="traces.jsonl",
        events_total=42,
        events_malformed=1,
        unrecognized_agent_ids={"retired_bot"},
        unrecognized_tool_ids={"sales_bot": {"unknown_tool"}},
        agents=[
            SimpleNamespace(
                agent_id="scheduler_bot", observed_in_trace=True, used_not_granted=["export_data"]
            ),
            SimpleNamespace(
                agent_id="clean_bot", observed_in_trace=True, used_not_granted=[]
            ),
            SimpleNamespace(
                agent_id="offline_bot", observed_in_trace=False, used_not_granted=[]
            ),
        ],
    )


def test_build_drift_payload_is_metadata_only() -> None:
    payload = build_drift_payload(_reconciliation(), fleet_agent_count=10)
    assert payload["event"] == "steward.drift_detected"
    assert payload["fleet_agents"] == 10
    assert payload["agents_observed"] == 2  # offline_bot was not observed
    assert payload["drift"]["used_not_granted"] == {"scheduler_bot": ["export_data"]}
    assert payload["drift"]["unrecognized_agents"] == ["retired_bot"]
    assert payload["drift"]["unrecognized_tools"] == {"sales_bot": ["unknown_tool"]}
    # Only identity metadata and counts — no free-form payload fields.
    dumped = json.dumps(payload)
    assert "argument" not in dumped and "result" not in dumped and "prompt" not in dumped


def test_post_drift_notification_delivers_json() -> None:
    received: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            received["body"] = json.loads(self.rfile.read(length))
            received["content_type"] = self.headers.get("Content-Type")
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):  # silence server logging
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        status = post_drift_notification(
            f"http://127.0.0.1:{port}", {"event": "steward.drift_detected"}
        )
    finally:
        thread.join(timeout=5)
        server.server_close()
    assert status == 200
    assert received["content_type"] == "application/json"
    assert received["body"] == {"event": "steward.drift_detected"}


def test_post_drift_notification_raises_on_unreachable() -> None:
    # Port 1 is not bindable by a normal service — connection is refused fast.
    with pytest.raises(NotifyError, match="failed"):
        post_drift_notification("http://127.0.0.1:1", {"event": "x"}, timeout=2.0)


def test_cli_notify_url_requires_traces(tmp_path, cli_text) -> None:
    result = runner.invoke(
        app,
        [
            "analyze",
            "--no-llm",
            "--notify-url",
            "http://127.0.0.1:9",
            "--state-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code != 0
    assert "requires --traces" in cli_text(result)
