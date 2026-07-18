(() => {
  "use strict";

  const jsonFromScript = (id) => {
    const node = document.getElementById(id);
    if (!node) return [];
    try { return JSON.parse(node.textContent || "[]"); } catch (_) { return []; }
  };

  const messageFor = async (response) => {
    try {
      const body = await response.json();
      return body.detail || body.message || "The request could not be completed.";
    } catch (_) {
      return "The request could not be completed.";
    }
  };

  const statusMessage = (target, text, kind) => {
    if (!target) return;
    target.textContent = text;
    target.classList.remove("error", "success");
    if (kind) target.classList.add(kind);
  };

  const drawGraph = () => {
    const canvas = document.getElementById("delegation-graph");
    if (!canvas) return;
    const allAgents = jsonFromScript("graph-agents");
    const edges = jsonFromScript("graph-edges");
    if (!allAgents.length) return;

    const riskRank = { critical: 4, high: 3, medium: 2, low: 1, clear: 0 };
    const touched = new Set(edges.flatMap((edge) => [edge.source, edge.target]));
    let agents = allAgents.filter((agent) => touched.has(agent.id) || riskRank[agent.risk_tier] > 0);
    if (agents.length < 2) agents = allAgents.slice(0, 10);
    // Keep a presentation graph legible; the full fleet remains in the cards.
    agents = agents.slice(0, 12);
    const visible = new Set(agents.map((agent) => agent.id));
    const graphEdges = edges.filter((edge) => visible.has(edge.source) && visible.has(edge.target));
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const colors = { critical: "#ff6c74", high: "#f4af57", medium: "#d8c66b", low: "#7ad5ad", clear: "#7aa6ff" };

    const draw = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const width = Math.max(260, Math.floor(rect.width));
      const height = Math.max(300, Math.floor(rect.height));
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);

      const count = agents.length;
      const radius = Math.max(90, Math.min(width, height) * .34);
      const centerX = width / 2;
      const centerY = height / 2 - 3;
      const positions = new Map();
      agents.forEach((agent, index) => {
        const angle = (-Math.PI / 2) + (index / count) * Math.PI * 2;
        positions.set(agent.id, {
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
          agent,
        });
      });

      // A subtle paper-like grid gives spatial context without implying data.
      ctx.strokeStyle = "rgba(126, 147, 191, .08)";
      ctx.lineWidth = 1;
      for (let x = 18; x < width; x += 36) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke(); }
      for (let y = 18; y < height; y += 36) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke(); }

      graphEdges.forEach((edge) => {
        const source = positions.get(edge.source);
        const target = positions.get(edge.target);
        if (!source || !target) return;
        const dx = target.x - source.x;
        const dy = target.y - source.y;
        const length = Math.hypot(dx, dy) || 1;
        const ux = dx / length;
        const uy = dy / length;
        const startX = source.x + ux * 19;
        const startY = source.y + uy * 19;
        const endX = target.x - ux * 25;
        const endY = target.y - uy * 25;
        ctx.strokeStyle = "rgba(150, 174, 226, .75)";
        ctx.lineWidth = 1.4;
        ctx.beginPath(); ctx.moveTo(startX, startY); ctx.lineTo(endX, endY); ctx.stroke();
        const arrow = 6;
        ctx.fillStyle = "#93a9d5";
        ctx.beginPath();
        ctx.moveTo(endX, endY);
        ctx.lineTo(endX - ux * arrow - uy * arrow * .55, endY - uy * arrow + ux * arrow * .55);
        ctx.lineTo(endX - ux * arrow + uy * arrow * .55, endY - uy * arrow - ux * arrow * .55);
        ctx.closePath(); ctx.fill();
      });

      positions.forEach(({ x, y, agent }) => {
        const color = colors[agent.risk_tier] || colors.clear;
        ctx.beginPath(); ctx.arc(x, y, 16, 0, Math.PI * 2); ctx.fillStyle = "#151d2b"; ctx.fill();
        ctx.lineWidth = 2.5; ctx.strokeStyle = color; ctx.stroke();
        ctx.beginPath(); ctx.arc(x, y, 5, 0, Math.PI * 2); ctx.fillStyle = color; ctx.fill();
        ctx.fillStyle = "#dbe4f8";
        ctx.font = "600 11px Inter, system-ui, sans-serif";
        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        const label = agent.name || agent.id;
        ctx.fillText(label.length > 19 ? `${label.slice(0, 18)}…` : label, x, y + 23);
      });
      if (!graphEdges.length) {
        ctx.fillStyle = "#8793aa";
        ctx.font = "12px Inter, system-ui, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("No delegation edges in this fleet", centerX, height - 24);
      }
    };
    draw();
    let resizeTimer;
    window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(draw, 90); });
  };

  const wireFindingFilters = () => {
    const filters = [...document.querySelectorAll("[data-finding-filter]")];
    const cards = [...document.querySelectorAll("[data-finding-card]")];
    const empty = document.querySelector("[data-no-filter-results]");
    filters.forEach((filter) => filter.addEventListener("click", () => {
      const active = filter.dataset.findingFilter;
      let shown = 0;
      cards.forEach((card) => {
        const show = active === "all" || card.dataset.checkType === active;
        card.hidden = !show;
        if (show) shown += 1;
      });
      filters.forEach((item) => item.classList.toggle("active", item === filter));
      if (empty) empty.hidden = shown !== 0;
    }));
  };

  const wireRunAnalysis = () => {
    document.querySelectorAll("[data-run-analysis]").forEach((button) => {
      button.addEventListener("click", async () => {
        const original = button.textContent;
        button.disabled = true;
        button.textContent = "Analyzing…";
        try {
          const response = await fetch("/api/analyze", { method: "POST" });
          if (!response.ok) throw new Error(await messageFor(response));
          window.location.reload();
        } catch (error) {
          button.textContent = error.message || "Analysis failed";
          setTimeout(() => { button.textContent = original; button.disabled = false; }, 2400);
        }
      });
    });
  };

  const wireConfigForm = () => {
    const form = document.querySelector("[data-load-fleet]");
    if (!form) return;
    const status = form.parentElement?.querySelector("[data-form-status]");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector("button[type='submit']");
      const formData = new FormData(form);
      const payload = Object.fromEntries(formData.entries());
      if (!payload.fleet_path) delete payload.fleet_path;
      if (!payload.tools_path) delete payload.tools_path;
      if (button) button.disabled = true;
      statusMessage(status, "Loading local config…");
      try {
        let response = await fetch("/api/fleet/load", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
        if (!response.ok) throw new Error(await messageFor(response));
        statusMessage(status, "Config loaded. Running verified checks…");
        response = await fetch("/api/analyze", { method: "POST" });
        if (!response.ok) throw new Error(await messageFor(response));
        statusMessage(status, "Analysis complete.", "success");
        window.setTimeout(() => window.location.reload(), 350);
      } catch (error) {
        statusMessage(status, error.message || "Unable to load the config.", "error");
        if (button) button.disabled = false;
      }
    });
  };

  const wireReviewForm = () => {
    document.querySelectorAll("[data-review-form]").forEach((form) => {
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const agentId = form.dataset.agentId;
        const status = form.querySelector("[data-form-status]");
        const button = form.querySelector("button[type='submit']");
        const payload = Object.fromEntries(new FormData(form).entries());
        if (button) button.disabled = true;
        statusMessage(status, "Saving decision…");
        try {
          const response = await fetch(`/api/risk-cards/${encodeURIComponent(agentId)}/review`, {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
          });
          if (!response.ok) throw new Error(await messageFor(response));
          statusMessage(status, "Review decision saved for this session.", "success");
          window.setTimeout(() => window.location.reload(), 350);
        } catch (error) {
          statusMessage(status, error.message || "Unable to save the decision.", "error");
        } finally {
          if (button) button.disabled = false;
        }
      });
    });
  };

  document.addEventListener("DOMContentLoaded", () => {
    drawGraph();
    wireFindingFilters();
    wireRunAnalysis();
    wireConfigForm();
    wireReviewForm();
  });
})();
