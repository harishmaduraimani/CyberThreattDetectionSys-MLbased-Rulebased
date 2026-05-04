// Intelligent Cyber Threat Detection System — frontend logic
(function () {
  "use strict";

  // ---------- helpers ----------
  function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function riskClass(score) {
    const s = Number(score) || 0;
    if (s >= 70) return "high";
    if (s >= 40) return "medium";
    return "low";
  }

  function show(el) { el.hidden = false; }
  function hide(el) { el.hidden = true; }

  function setLoading(btn, loadingEl, isLoading) {
    if (btn) btn.disabled = isLoading;
    if (loadingEl) loadingEl.hidden = !isLoading;
  }

  function setError(el, message) {
    if (!message) { el.hidden = true; el.textContent = ""; return; }
    el.hidden = false;
    el.textContent = message;
  }

  // ---------- result rendering ----------
  function renderResult(targetEl, data, paramOrder) {
    if (!data) { targetEl.innerHTML = '<div class="result-empty">No data.</div>'; return; }
    const score = Number(data.risk_score) || 0;
    const cls = riskClass(score);
    const params = data.parameters || {};
    const order = paramOrder && paramOrder.length
      ? paramOrder.filter((k) => k in params).concat(Object.keys(params).filter((k) => paramOrder.indexOf(k) === -1))
      : Object.keys(params);

    let rows = "";
    order.forEach((key) => {
      let val = params[key];
      if (Array.isArray(val)) val = val.join(", ");
      else if (val !== null && typeof val === "object") val = JSON.stringify(val);
      rows += `<tr><td>${escapeHtml(key)}</td><td>${escapeHtml(val)}</td></tr>`;
    });

    targetEl.innerHTML = `
      <div class="result">
        <div class="result-summary">
          <div class="risk-score ${cls}">${escapeHtml(score)}</div>
          <div class="verdict-block">
            <div class="verdict-label">${escapeHtml(data.detector || data.scan_type || "Scan")}</div>
            <div class="verdict-value">${escapeHtml(data.verdict || "—")}</div>
            <div class="reason">${escapeHtml(data.reason || "")}</div>
          </div>
          <span class="badge ${cls}">${cls === "high" ? "High risk" : cls === "medium" ? "Medium" : "Low risk"}</span>
        </div>
        ${data.timestamp ? `<div class="muted" style="font-size:12px;font-family:var(--mono)">Scanned at ${escapeHtml(data.timestamp)}</div>` : ""}
        <div class="params-section">
          <h3>Extracted parameters</h3>
          <table class="params-table"><tbody>${rows || '<tr><td colspan="2">No parameters returned.</td></tr>'}</tbody></table>
        </div>
      </div>
    `;
  }

  function renderPortResult(targetEl, data) {
    if (!data) { targetEl.innerHTML = '<div class="result-empty">No data.</div>'; return; }
    const score = Number(data.risk_score) || 0;
    const cls = riskClass(score);
    const p = data.parameters || {};
    const openPorts = Array.isArray(p.open_ports) ? p.open_ports : [];
    const services = p.service_name && typeof p.service_name === "object" ? p.service_name : {};

    let portsRows = "";
    openPorts.forEach((port) => {
      const svc = services[port] || services[String(port)] || "unknown";
      portsRows += `<tr><td>${escapeHtml(port)}</td><td>${escapeHtml(svc)}</td></tr>`;
    });

    const scannedPorts = Array.isArray(p.scanned_ports) ? p.scanned_ports.join(", ") : escapeHtml(p.scanned_ports || "");

    targetEl.innerHTML = `
      <div class="result">
        <div class="result-summary">
          <div class="risk-score ${cls}">${escapeHtml(score)}</div>
          <div class="verdict-block">
            <div class="verdict-label">${escapeHtml(data.detector || "Port Scanner")}</div>
            <div class="verdict-value">${escapeHtml(data.verdict || "—")}</div>
            <div class="reason">${escapeHtml(data.reason || "")}</div>
          </div>
          <span class="badge ${cls}">${cls === "high" ? "High risk" : cls === "medium" ? "Medium" : "Low risk"}</span>
        </div>
        ${data.timestamp ? `<div class="muted" style="font-size:12px;font-family:var(--mono)">Scanned at ${escapeHtml(data.timestamp)}</div>` : ""}
        <div class="params-section">
          <h3>Target</h3>
          <table class="params-table"><tbody>
            <tr><td>target_host</td><td>${escapeHtml(p.target_host || "")}</td></tr>
            <tr><td>scanned_ports</td><td>${scannedPorts}</td></tr>
            <tr><td>open_port_count</td><td>${escapeHtml(p.open_port_count != null ? p.open_port_count : openPorts.length)}</td></tr>
          </tbody></table>
        </div>
        <div class="params-section">
          <h3>Open ports</h3>
          ${openPorts.length ? `
            <table class="ports-table">
              <thead><tr><th>Port</th><th>Service</th></tr></thead>
              <tbody>${portsRows}</tbody>
            </table>` : '<div class="muted">No open ports detected.</div>'}
        </div>
      </div>
    `;
  }

  // ---------- tabs ----------
  const navItems = document.querySelectorAll(".nav-item");
  const panels = document.querySelectorAll(".tab-panel");
  const topbarTitle = document.getElementById("topbarTitle");
  const topbarMeta = document.getElementById("topbarMeta");
  const sidebar = document.getElementById("sidebar");
  document.getElementById("menuBtn").addEventListener("click", () => sidebar.classList.toggle("open"));

  const tabMeta = {
    file: { title: "File Malware Scanner", meta: "Static analysis · SHA-256" },
    url: { title: "URL Detector", meta: "Rule + ML phishing analysis" },
    ports: { title: "Port Scanner", meta: "Network discovery" },
    ai: { title: "AI Assistant", meta: "Conversational analyst" },
    history: { title: "Scan History", meta: "Recent activity" },
  };

  navItems.forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.tab;
      navItems.forEach((b) => b.classList.toggle("active", b === btn));
      panels.forEach((p) => p.classList.toggle("active", p.id === "tab-" + tab));
      const meta = tabMeta[tab];
      if (meta) { topbarTitle.textContent = meta.title; topbarMeta.textContent = meta.meta; }
      if (tab === "history") loadHistory();
      if (window.innerWidth <= 720) sidebar.classList.remove("open");
    });
  });

  // ---------- File tab ----------
  const fileForm = document.getElementById("fileForm");
  const fileInput = document.getElementById("fileInput");
  const fileLabel = document.getElementById("fileLabel");
  const fileLoading = document.getElementById("fileLoading");
  const fileError = document.getElementById("fileError");
  const fileResult = document.getElementById("fileResult");

  fileInput.addEventListener("change", () => {
    fileLabel.textContent = fileInput.files[0] ? fileInput.files[0].name : "Choose a file to upload";
  });

  const FILE_PARAMS = ["file_name","file_extension","file_size_bytes","sha256_hash","has_double_extension","hash_matched_malware_database"];

  fileForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!fileInput.files[0]) return;
    setError(fileError, "");
    setLoading(fileForm.querySelector("button"), fileLoading, true);
    try {
      const fd = new FormData();
      fd.append("file", fileInput.files[0]);
      const res = await fetch("/api/scan/file", { method: "POST", body: fd });
      if (!res.ok) throw new Error("Server returned " + res.status);
      const data = await res.json();
      renderResult(fileResult, data, FILE_PARAMS);
    } catch (err) {
      setError(fileError, "Failed to scan file: " + err.message);
    } finally {
      setLoading(fileForm.querySelector("button"), fileLoading, false);
    }
  });

  // ---------- URL tab ----------
  const urlForm = document.getElementById("urlForm");
  const urlInput = document.getElementById("urlInput");
  const urlLoading = document.getElementById("urlLoading");
  const urlError = document.getElementById("urlError");
  const urlResult = document.getElementById("urlResult");

  const URL_PARAMS = ["url_length","uses_http","uses_https","uses_ip","suspicious_word_count","has_at_symbol","dot_count","hyphen_count","path_length","domain_age_days","redirect_count","final_url","rule_based_score","ml_risk_score","final_score"];

  urlForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    setError(urlError, "");
    setLoading(urlForm.querySelector("button"), urlLoading, true);
    try {
      const res = await fetch("/api/scan/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlInput.value.trim() }),
      });
      if (!res.ok) throw new Error("Server returned " + res.status);
      const data = await res.json();
      renderResult(urlResult, data, URL_PARAMS);
    } catch (err) {
      setError(urlError, "Failed to scan URL: " + err.message);
    } finally {
      setLoading(urlForm.querySelector("button"), urlLoading, false);
    }
  });

  // ---------- Port tab ----------
  const portForm = document.getElementById("portForm");
  const hostInput = document.getElementById("hostInput");
  const portsInput = document.getElementById("portsInput");
  const portLoading = document.getElementById("portLoading");
  const portError = document.getElementById("portError");
  const portResult = document.getElementById("portResult");

  portForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    setError(portError, "");
    setLoading(portForm.querySelector("button"), portLoading, true);
    try {
      const payload = { host: hostInput.value.trim() };
      const portsRaw = portsInput.value.trim();
      if (portsRaw) {
        payload.ports = portsRaw.split(",").map((p) => parseInt(p.trim(), 10)).filter((n) => !isNaN(n));
      }
      const res = await fetch("/api/scan/ports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error("Server returned " + res.status);
      const data = await res.json();
      renderPortResult(portResult, data);
    } catch (err) {
      setError(portError, "Failed to scan ports: " + err.message);
    } finally {
      setLoading(portForm.querySelector("button"), portLoading, false);
    }
  });

  // ---------- AI Assistant ----------
  const chatMessages = document.getElementById("chatMessages");
  const chatForm = document.getElementById("chatForm");
  const chatInput = document.getElementById("chatInput");
  const chatSend = document.getElementById("chatSend");

  function appendMessage(role, text, opts) {
    const wrap = document.createElement("div");
    wrap.className = "msg " + role;
    const bubble = document.createElement("div");
    bubble.className = "bubble" + (opts && opts.typing ? " typing" : "");
    bubble.textContent = text;
    wrap.appendChild(bubble);
    chatMessages.appendChild(wrap);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return bubble;
  }

  appendMessage("assistant", "Hello! I'm your security analyst assistant. Ask me about scan results, indicators of compromise, or general cybersecurity questions.");

  chatInput.addEventListener("input", () => {
    chatInput.style.height = "auto";
    chatInput.style.height = Math.min(chatInput.scrollHeight, 160) + "px";
  });
  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); chatForm.requestSubmit(); }
  });

  chatForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const message = chatInput.value.trim();
    if (!message) return;
    appendMessage("user", message);
    chatInput.value = "";
    chatInput.style.height = "auto";
    chatSend.disabled = true;
    const typing = appendMessage("assistant", "Thinking…", { typing: true });
    try {
      const res = await fetch("/api/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message }),
      });
      if (!res.ok) throw new Error("Server returned " + res.status);
      const data = await res.json();
      typing.classList.remove("typing");
      typing.textContent = data.reply || data.answer || data.response || "(no response)";
    } catch (err) {
      typing.classList.remove("typing");
      typing.textContent = "Error: " + err.message;
    } finally {
      chatSend.disabled = false;
      chatMessages.scrollTop = chatMessages.scrollHeight;
    }
  });

  // ---------- History ----------
  const historyList = document.getElementById("historyList");
  const historyLoading = document.getElementById("historyLoading");
  const historyError = document.getElementById("historyError");
  const historyResult = document.getElementById("historyResult");
  document.getElementById("refreshHistory").addEventListener("click", loadHistory);

  async function loadHistory() {
    setError(historyError, "");
    historyLoading.hidden = false;
    historyList.innerHTML = "";
    try {
      const res = await fetch("/api/history");
      if (!res.ok) throw new Error("Server returned " + res.status);
      const items = await res.json();
      if (!Array.isArray(items) || items.length === 0) {
        historyList.innerHTML = '<li class="muted" style="padding:8px">No scans recorded yet.</li>';
        return;
      }
      items.forEach((item, idx) => {
        const li = document.createElement("li");
        li.className = "history-item";
        const cls = riskClass(item.risk_score);
        li.innerHTML = `
          <div>
            <div class="h-type">${escapeHtml(item.detector || item.scan_type || "Scan")}</div>
            <div class="h-time">${escapeHtml(item.timestamp || "")}</div>
            <div class="h-verdict">${escapeHtml(item.verdict || "")}</div>
          </div>
          <div style="text-align:right">
            <span class="badge ${cls}">${escapeHtml(item.risk_score != null ? item.risk_score : "—")}</span>
          </div>
        `;
        li.addEventListener("click", () => {
          document.querySelectorAll(".history-item").forEach((el) => el.classList.remove("active"));
          li.classList.add("active");
          if ((item.scan_type || "").toLowerCase().indexOf("port") !== -1) {
            renderPortResult(historyResult, item);
          } else {
            renderResult(historyResult, item);
          }
        });
        historyList.appendChild(li);
      });
    } catch (err) {
      setError(historyError, "Failed to load history: " + err.message);
    } finally {
      historyLoading.hidden = true;
    }
  }
})();
