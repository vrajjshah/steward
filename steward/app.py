"""FastAPI application for Steward's local demo and review workflow.

Run locally with::

    STEWARD_DEMO=1 uvicorn steward.app:app --reload

The API only returns verified findings and deliberately selected configuration
metadata.  It never returns MCP environment variables, command arguments, or
agent payload data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from steward.reporting import render_markdown_report
from steward.web_service import StewardService, _redact_error

APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))


class LoadFleetRequest(BaseModel):
    """A local config request. Paths are intentionally never echoed verbatim."""

    fleet_path: str | None = Field(default=None, description="Path to fleet JSON or MCP config")
    tools_path: str | None = Field(default=None, description="Path to tool catalog JSON")
    source_type: Literal["fleet", "mcp", "mcp_json", "mcp-config"] = "fleet"


class ReviewDecision(BaseModel):
    status: Literal["approve", "revoke", "flag", "pending"]
    note: str = Field(default="", max_length=2_000)


def _http_error(error: Exception, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR) -> HTTPException:
    return HTTPException(status_code=status_code, detail=_redact_error(error))


def _dashboard_context(request: Request, service: StewardService) -> dict[str, Any]:
    """Create a display-safe context, including an intentional empty/error state."""

    try:
        current = service.current()
        report = current["report"]
        cards = report["certification_packet"]["risk_cards"]
        findings = current["findings"]
        # The demo deliberately opens on the tangible data-exfiltration path;
        # only fall back when an imported fleet does not contain that example.
        hero_finding = next(
            (
                finding
                for finding in findings
                if finding["agent_id"] == "support_bot"
                and finding.get("rule_id") == "sensitive_data_external_egress"
            ),
            next(
                (finding for finding in findings if finding["agent_id"] == "support_bot"),
                findings[0] if findings else None,
            ),
        )
        # The deterministic exfiltration path remains the opening beat. When
        # the analysis also contains a graph-cited model-generalized result,
        # surface one compact second beat immediately beneath it so the demo
        # makes the two evidence tiers visible without requiring a scroll.
        second_beat_finding = next(
            (
                finding
                for finding in findings
                if finding.get("source") == "llm_generalized"
            ),
            None,
        )
        risk_by_agent = {card["agent"]["id"]: card["risk_tier"] for card in cards}
        graph_agents = [
            {
                "id": agent["id"],
                "name": agent["name"],
                "owner": agent["owner"],
                "risk_tier": risk_by_agent.get(agent["id"], "clear"),
            }
            for agent in current["fleet"]["agents"]
        ]
        return {
            "request": request,
            "ready": True,
            "error": None,
            "current": current,
            "report": report,
            "findings": findings,
            "hero_finding": hero_finding,
            "second_beat_finding": second_beat_finding,
            "risk_cards": cards,
            "graph_agents": graph_agents,
            "graph_edges": report["delegation_edges"],
            "severity_counts": report["executive_summary"]["severity_counts"],
        }
    except Exception as error:  # The app should still explain a local setup problem.
        return {
            "request": request,
            "ready": False,
            "error": _redact_error(error),
            "current": None,
            "report": None,
            "findings": [],
            "hero_finding": None,
            "second_beat_finding": None,
            "risk_cards": [],
            "graph_agents": [],
            "graph_edges": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }


def create_app(service: StewardService | None = None) -> FastAPI:
    """Create an app that can be dependency-injected in API/UI tests."""

    app = FastAPI(
        title="Steward",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.steward = service or StewardService()
    app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")

    def steward() -> StewardService:
        return app.state.steward

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context=_dashboard_context(request, steward()),
        )

    @app.get("/risk-cards/{agent_id}", response_class=HTMLResponse, include_in_schema=False)
    def risk_card_page(agent_id: str, request: Request) -> HTMLResponse:
        try:
            card = steward().risk_card(agent_id)
        except KeyError as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Risk card not found."
            ) from error
        except Exception as error:
            raise _http_error(error) from error
        return templates.TemplateResponse(
            request=request,
            name="risk_card.html",
            context={"request": request, "card": card},
        )

    @app.get("/report", response_class=HTMLResponse, include_in_schema=False)
    def report_page(request: Request) -> HTMLResponse:
        try:
            report = steward().report()
        except Exception as error:
            return templates.TemplateResponse(
                request=request,
                name="report.html",
                context={"request": request, "report": None, "error": _redact_error(error)},
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return templates.TemplateResponse(
            request=request,
            name="report.html",
            context={"request": request, "report": report, "error": None},
        )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "steward"}

    @app.get("/api/fleet")
    def get_fleet() -> dict[str, Any]:
        try:
            return steward().fleet_summary()
        except Exception as error:
            raise _http_error(error) from error

    @app.post("/api/fleet/load")
    def load_fleet(payload: LoadFleetRequest) -> dict[str, Any]:
        try:
            return steward().load_fleet(
                fleet_path=payload.fleet_path,
                tools_path=payload.tools_path,
                source_type=payload.source_type,
            )
        except FileNotFoundError as error:
            raise _http_error(error, status.HTTP_404_NOT_FOUND) from error
        except (RuntimeError, ValueError) as error:
            raise _http_error(error, status.HTTP_422_UNPROCESSABLE_ENTITY) from error
        except Exception as error:
            raise _http_error(error) from error

    @app.post("/api/analyze")
    def analyze(force: bool = True) -> dict[str, Any]:
        try:
            return steward().analyze(force=force)
        except Exception as error:
            raise _http_error(error) from error

    @app.get("/api/findings")
    def get_findings(
        check_type: Annotated[str | None, Query()] = None,
        severity: Annotated[str | None, Query()] = None,
    ) -> dict[str, Any]:
        try:
            findings = steward().current()["findings"]
        except Exception as error:
            raise _http_error(error) from error
        if check_type:
            findings = [item for item in findings if item["check_type"] == check_type]
        if severity:
            findings = [item for item in findings if item["severity"] == severity.lower()]
        return {"findings": findings, "count": len(findings)}

    @app.get("/api/risk-cards")
    def get_risk_cards() -> dict[str, Any]:
        try:
            packet = steward().certification_packet()
            return {"risk_cards": packet["risk_cards"], "summary": packet["summary"]}
        except Exception as error:
            raise _http_error(error) from error

    @app.get("/api/risk-cards/{agent_id}")
    def get_risk_card(agent_id: str) -> dict[str, Any]:
        try:
            return steward().risk_card(agent_id)
        except KeyError as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Risk card not found."
            ) from error
        except Exception as error:
            raise _http_error(error) from error

    @app.post("/api/risk-cards/{agent_id}/review")
    def review_risk_card(agent_id: str, decision: ReviewDecision) -> dict[str, Any]:
        try:
            return steward().record_review(agent_id, decision.status, decision.note)
        except KeyError as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Risk card not found."
            ) from error
        except ValueError as error:
            raise _http_error(error, status.HTTP_422_UNPROCESSABLE_ENTITY) from error
        except Exception as error:
            raise _http_error(error) from error

    @app.get("/api/report")
    def get_report() -> dict[str, Any]:
        try:
            return steward().report()
        except Exception as error:
            raise _http_error(error) from error

    @app.get("/api/certification-packet")
    def get_certification_packet() -> dict[str, Any]:
        try:
            return steward().certification_packet()
        except Exception as error:
            raise _http_error(error) from error

    @app.get("/api/certification-packet.json")
    def export_certification_packet() -> JSONResponse:
        try:
            return JSONResponse(
                steward().certification_packet(),
                headers={
                    "Content-Disposition": 'attachment; filename="steward-certification-packet.json"'
                },
            )
        except Exception as error:
            raise _http_error(error) from error

    @app.get("/api/report.json")
    def export_report_json() -> JSONResponse:
        try:
            return JSONResponse(
                steward().report(),
                headers={"Content-Disposition": 'attachment; filename="steward-audit-report.json"'},
            )
        except Exception as error:
            raise _http_error(error) from error

    @app.get("/api/report.md")
    def export_report_markdown() -> PlainTextResponse:
        try:
            report = steward().report()
            return PlainTextResponse(
                render_markdown_report(report),
                media_type="text/markdown",
                headers={"Content-Disposition": 'attachment; filename="steward-audit-report.md"'},
            )
        except Exception as error:
            raise _http_error(error) from error

    @app.get("/api/report.html", response_class=HTMLResponse)
    def export_report_html(request: Request) -> HTMLResponse:
        try:
            report = steward().report()
        except Exception as error:
            raise _http_error(error) from error
        return templates.TemplateResponse(
            request=request,
            name="report.html",
            context={"request": request, "report": report, "error": None, "export": True},
            headers={"Content-Disposition": 'attachment; filename="steward-audit-report.html"'},
        )

    return app


app = create_app()
