"""Serve the one bundled synthetic MCP upstream used by the red-team demo."""

from __future__ import annotations

import uvicorn

from steward.redteam import create_demo_upstream_app

app = create_demo_upstream_app()


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765)
