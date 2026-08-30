/* dashboard.js -- talks to the Flask REST API and renders the console. */
(function () {
  "use strict";

  const COLORS = {
    signal: "#00d9c0",
    critical: "#ff3b5c",
    high: "#ff8a3d",
    medium: "#ffd23d",
    low: "#4e9fff",
    other: "#7686a3",
    textMuted: "#7686a3",
    grid: "rgba(126, 148, 184, 0.12)",
  };
  const PROTO_COLOR = { TCP: COLORS.signal, UDP: COLORS.low, ICMP: COLORS.high, Other: COLORS.other };

  const state = {
    mode: "simulation",
    running: false,
    sessionStart: null,
    activeTab: "overview",
    seenAlertIds: new Set(),
    scapyAvailable: window.NIDS_CONFIG.scapyAvailable,
  };

  // ------------------------------------------------------------- helpers

  function $(id) { return document.getElementById(id); }

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function fmtTime(ts) {
    if (!ts) return "--";
    return new Date(ts * 1000).toLocaleTimeString();
  }

  function fmtDateTime(ts) {
    if (!ts) return "--";
    return new Date(ts * 1000).toLocaleString();
  }

  function fmtNum(n) { return (n || 0).toLocaleString(); }

  function fmtUptime(startTs) {
    if (!startTs) return "00:00:00";
    let s = Math.max(0, Math.floor(Date.now() / 1000 - startTs));
    const h = String(Math.floor(s / 3600)).padStart(2, "0");
    const m = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
    const sec = String(s % 60).padStart(2, "0");
    return `${h}:${m}:${sec}`;
  }

  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, opts));
    if (res.status === 401) {
      window.location.href = "/login";
      throw new Error("Not authenticated");
    }
    return res;
  }

  function toast(message, type) {
    const stack = $("toastStack");
    const el = document.createElement("div");
    el.className = `nids-toast ${type || ""}`;
    el.textContent = message;
    stack.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  function severityBadge(sev) {
    return `<span class="sev-badge sev-${escapeHtml(sev)}">${escapeHtml(sev)}</span>`;
  }

  // -------------------------------------------------------------- tabs

  document.querySelectorAll("#mainTabs .nav-link").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#mainTabs .nav-link").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      state.activeTab = tab;
      $("tab-overview").style.display = tab === "overview" ? "" : "none";
      $("tab-reports").style.display = tab === "reports" ? "" : "none";
      if (tab === "reports") refreshReports();
    });
  });

  // ---------------------------------------------------------- controls

  const modeButtons = document.querySelectorAll("#modeToggle button");
  modeButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.disabled) return;
      modeButtons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.mode = btn.dataset.mode;
      $("interfaceSelect").style.display = state.mode === "live" ? "" : "none";
    });
  });

  if (!state.scapyAvailable) {
    const liveBtn = document.querySelector('#modeToggle button[data-mode="live"]');
    liveBtn.disabled = true;
    liveBtn.title = "Scapy is not installed in this environment.";
    $("scapyWarn").style.display = "";
  }

  async function loadInterfaces() {
    try {
      const res = await api("/api/interfaces");
      const data = await res.json();
      const sel = $("interfaceSelect");
      (data.interfaces || []).forEach((iface) => {
        const opt = document.createElement("option");
        opt.value = iface;
        opt.textContent = iface;
        sel.appendChild(opt);
      });
    } catch (e) { /* non-fatal */ }
  }

  $("startBtn").addEventListener("click", async () => {
    $("captureErr").style.display = "none";
    const body = { mode: state.mode, interface: $("interfaceSelect").value || null };
    try {
      const res = await api("/api/capture/start", { method: "POST", body: JSON.stringify(body) });
      const data = await res.json();
      if (!data.success) {
        $("captureErr").textContent = data.message || "Could not start capture.";
        $("captureErr").style.display = "";
        toast(data.message || "Could not start capture.", "error");
        return;
      }
      state.seenAlertIds.clear();
      toast(`${state.mode === "live" ? "Live capture" : "Simulation"} started.`, "success");
      await refreshStatus();
    } catch (e) { /* handled by api() redirect on 401 */ }
  });

  $("stopBtn").addEventListener("click", async () => {
    await api("/api/capture/stop", { method: "POST" });
    toast("Monitoring stopped.", "success");
    await refreshStatus();
  });

  function applyRunningUI(running, mode) {
    $("startBtn").style.display = running ? "none" : "";
    $("stopBtn").style.display = running ? "" : "none";
    modeButtons.forEach((b) => (b.disabled = running || (b.dataset.mode === "live" && !state.scapyAvailable)));
    $("interfaceSelect").disabled = running;

    const pill = $("statusPill");
    const pillText = $("statusPillText");
    if (running) {
      pill.classList.add("live");
      pillText.textContent = mode === "live" ? "LIVE" : "SIMULATING";
    } else {
      pill.classList.remove("live");
      pillText.textContent = "OFFLINE";
    }
    $("statMode").textContent = running ? (mode === "live" ? "live capture" : "simulation mode") : "not running";
  }

  // ------------------------------------------------------------ status

  async function refreshStatus() {
    try {
      const res = await api("/api/capture/status");
      const data = await res.json();
      state.running = data.running;
      state.mode = data.mode || state.mode;
      state.sessionStart = data.start_time;
      applyRunningUI(data.running, data.mode);

      if (data.error) {
        $("captureErr").textContent = data.error;
        $("captureErr").style.display = "";
      } else {
        $("captureErr").style.display = "none";
      }
    } catch (e) { /* ignore transient errors */ }
  }

  setInterval(() => {
    $("statUptime").textContent = state.running ? fmtUptime(state.sessionStart) : "00:00:00";
  }, 1000);

  // ------------------------------------------------------------- charts

  Chart.defaults.color = COLORS.textMuted;
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size = 11;

  const trafficChart = new Chart($("trafficChart").getContext("2d"), {
    type: "line",
    data: { labels: [], datasets: [{
      label: "packets/sec", data: [], borderColor: COLORS.signal,
      backgroundColor: "rgba(0, 217, 192, 0.12)", fill: true, tension: 0.35,
      pointRadius: 0, borderWidth: 2,
    }] },
    options: {
      responsive: true, maintainAspectRatio: false, animation: { duration: 250 },
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: COLORS.grid }, ticks: { maxTicksLimit: 8 } },
        y: { grid: { color: COLORS.grid }, beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });

  const protocolChart = new Chart($("protocolChart").getContext("2d"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 0 }] },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: "68%",
      plugins: { legend: { position: "bottom", labels: { boxWidth: 10, padding: 10 } } },
    },
  });

  const alertsByDayChart = new Chart($("alertsByDayChart").getContext("2d"), {
    type: "bar",
    data: { labels: [], datasets: [{ label: "alerts", data: [], backgroundColor: COLORS.signal, borderRadius: 3 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { grid: { color: COLORS.grid }, beginAtZero: true, ticks: { precision: 0 } },
      },
    },
  });

  const alertsByTypeChart = new Chart($("alertsByTypeChart").getContext("2d"), {
    type: "bar",
    data: { labels: [], datasets: [{ label: "alerts", data: [], backgroundColor: COLORS.low, borderRadius: 3 }] },
    options: {
      indexAxis: "y", responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: COLORS.grid }, beginAtZero: true, ticks: { precision: 0 } },
        y: { grid: { display: false } },
      },
    },
  });

  // -------------------------------------------------------- overview data

  async function refreshStats() {
    try {
      const res = await api("/api/stats");
      const s = await res.json();

      $("statPackets").textContent = fmtNum(s.total_packets);
      const alertTotal = Object.values(s.severity_counts || {}).reduce((a, b) => a + b, 0);
      $("statAlerts").textContent = fmtNum(alertTotal);
      $("statCritical").textContent = fmtNum((s.severity_counts || {}).Critical || 0);

      trafficChart.data.labels = (s.timeline || []).map((p) => fmtTime(p.t));
      trafficChart.data.datasets[0].data = (s.timeline || []).map((p) => p.count);
      trafficChart.update("none");

      const protoEntries = Object.entries(s.protocol_counts || {});
      protocolChart.data.labels = protoEntries.map((e) => e[0]);
      protocolChart.data.datasets[0].data = protoEntries.map((e) => e[1]);
      protocolChart.data.datasets[0].backgroundColor = protoEntries.map((e) => PROTO_COLOR[e[0]] || COLORS.other);
      protocolChart.update("none");

      const maxTalker = Math.max(1, ...(s.top_talkers || []).map((t) => t.count));
      $("topTalkers").innerHTML = (s.top_talkers || []).map((t) => `
        <div class="top-talker-bar">
          <span class="ip">${escapeHtml(t.ip)}</span>
          <span class="bar-track"><span class="bar-fill" style="width:${(t.count / maxTalker) * 100}%"></span></span>
          <span class="count">${fmtNum(t.count)}</span>
        </div>`).join("") || `<div class="empty-state">No traffic yet</div>`;
    } catch (e) { /* ignore transient errors */ }
  }

  async function refreshLiveAlerts() {
    try {
      const res = await api("/api/alerts?limit=30");
      const data = await res.json();
      const alerts = data.alerts || [];
      $("liveAlertsMeta").textContent = `${alerts.length} recent`;
      $("liveAlertsEmpty").style.display = alerts.length ? "none" : "";

      $("liveAlertsBody").innerHTML = alerts.map((a) => {
        const isNew = !state.seenAlertIds.has(a.id);
        state.seenAlertIds.add(a.id);
        return `<tr class="alert-row sev-${escapeHtml(a.severity)} ${isNew ? "is-new" : ""}">
          <td class="ts">${fmtTime(a.timestamp)}</td>
          <td>${severityBadge(a.severity)}</td>
          <td>${escapeHtml(a.alert_type)}</td>
          <td class="ip">${escapeHtml(a.src_ip || "--")}</td>
          <td class="ip">${escapeHtml(a.dst_ip || "--")}</td>
          <td class="desc">${escapeHtml(a.description)}</td>
        </tr>`;
      }).join("");
    } catch (e) { /* ignore transient errors */ }
  }

  async function refreshTraffic() {
    try {
      const res = await api("/api/traffic?limit=15");
      const data = await res.json();
      const packets = data.packets || [];
      $("trafficEmpty").style.display = packets.length ? "none" : "";
      $("trafficBody").innerHTML = packets.map((p) => `
        <tr>
          <td class="ts">${fmtTime(p.timestamp)}</td>
          <td class="ip">${escapeHtml(p.src_ip || "--")}</td>
          <td class="ip">${escapeHtml(p.dst_ip || "--")}</td>
          <td><span class="proto-badge">${escapeHtml(p.protocol)}</span></td>
          <td class="num">${p.dst_port || "--"}</td>
          <td class="num">${fmtNum(p.size)} B</td>
        </tr>`).join("");
    } catch (e) { /* ignore transient errors */ }
  }

  // --------------------------------------------------------- reports data

  async function refreshReports() {
    try {
      const res = await api("/api/reports");
      const r = await res.json();

      $("repPackets").textContent = fmtNum(r.total_packets_logged);
      const totalAlerts = Object.values(r.alerts_by_severity || {}).reduce((a, b) => a + b, 0);
      $("repAlerts").textContent = fmtNum(totalAlerts);
      $("repCritical").textContent = fmtNum((r.alerts_by_severity || {}).Critical || 0);
      $("repHigh").textContent = fmtNum((r.alerts_by_severity || {}).High || 0);

      alertsByDayChart.data.labels = (r.alerts_by_day || []).map((d) => d.day.slice(5));
      alertsByDayChart.data.datasets[0].data = (r.alerts_by_day || []).map((d) => d.count);
      alertsByDayChart.update("none");

      alertsByTypeChart.data.labels = (r.alerts_by_type || []).map((d) => d.alert_type);
      alertsByTypeChart.data.datasets[0].data = (r.alerts_by_type || []).map((d) => d.count);
      alertsByTypeChart.update("none");

      const maxSrc = Math.max(1, ...(r.top_sources || []).map((s) => s.count));
      $("topSourcesEmpty").style.display = (r.top_sources || []).length ? "none" : "";
      $("topSourcesBody").innerHTML = (r.top_sources || []).map((s) => `
        <tr>
          <td class="ip">${escapeHtml(s.src_ip)}</td>
          <td class="num">${fmtNum(s.count)}</td>
          <td><span class="bar-track" style="display:inline-block; width:120px; height:5px; background:var(--bg-panel-raised); border-radius:3px; overflow:hidden;"><span style="display:block; height:100%; width:${(s.count / maxSrc) * 100}%; background:var(--sev-high);"></span></span></td>
        </tr>`).join("");

      await refreshHistory();
    } catch (e) { /* ignore transient errors */ }
  }

  async function refreshHistory() {
    const severity = $("historyFilter").value;
    const url = "/api/alerts?limit=200" + (severity ? `&severity=${encodeURIComponent(severity)}` : "");
    try {
      const res = await api(url);
      const data = await res.json();
      const alerts = data.alerts || [];
      $("historyEmpty").style.display = alerts.length ? "none" : "";
      $("historyBody").innerHTML = alerts.map((a) => `
        <tr class="alert-row sev-${escapeHtml(a.severity)}">
          <td class="ts">${fmtDateTime(a.timestamp)}</td>
          <td>${severityBadge(a.severity)}</td>
          <td>${escapeHtml(a.alert_type)}</td>
          <td class="ip">${escapeHtml(a.src_ip || "--")}</td>
          <td class="ip">${escapeHtml(a.dst_ip || "--")}</td>
          <td class="desc">${escapeHtml(a.description)}</td>
        </tr>`).join("");
    } catch (e) { /* ignore transient errors */ }
  }

  $("historyFilter").addEventListener("change", refreshHistory);

  // Only admins get this button rendered server-side (see index.html) --
  // guard it here too so a non-admin session never throws on a missing
  // element and breaks every polling/init call that follows in this file.
  const resetDataBtn = $("resetDataBtn");
  if (resetDataBtn) {
    resetDataBtn.addEventListener("click", async () => {
      if (!confirm("Clear all stored packets and alerts? This can't be undone.")) return;
      await api("/api/admin/reset-data", { method: "POST" });
      state.seenAlertIds.clear();
      toast("Demo data cleared.", "success");
      refreshReports();
      refreshStats();
      refreshLiveAlerts();
      refreshTraffic();
    });
  }

  // -------------------------------------------------------- change password

  $("submitChangePassword").addEventListener("click", async () => {
    const current = $("currentPassword").value;
    const next = $("newPassword").value;
    const confirmPw = $("confirmPassword").value;
    const errBox = $("changePwError");
    errBox.style.display = "none";

    if (next !== confirmPw) {
      errBox.textContent = "New passwords don't match.";
      errBox.style.display = "";
      return;
    }
    try {
      const res = await api("/api/account/change-password", {
        method: "POST",
        body: JSON.stringify({ current_password: current, new_password: next }),
      });
      const data = await res.json();
      if (!data.success) {
        errBox.textContent = data.message;
        errBox.style.display = "";
        return;
      }
      toast("Password updated.", "success");
      $("currentPassword").value = "";
      $("newPassword").value = "";
      $("confirmPassword").value = "";
      bootstrap.Modal.getInstance($("changePasswordModal")).hide();
      const banner = $("defaultPwBanner");
      if (banner) banner.remove();
    } catch (e) { /* handled by api() redirect on 401 */ }
  });

  // ----------------------------------------------------------------- init

  async function init() {
    await loadInterfaces();
    await refreshStatus();
    await refreshStats();
    await refreshLiveAlerts();
    await refreshTraffic();

    setInterval(refreshStatus, 2000);
    setInterval(() => { if (state.activeTab === "overview") refreshStats(); }, 2000);
    setInterval(() => { if (state.activeTab === "overview") refreshLiveAlerts(); }, 3000);
    setInterval(() => { if (state.activeTab === "overview") refreshTraffic(); }, 3000);
    setInterval(() => { if (state.activeTab === "reports") refreshReports(); }, 5000);
  }

  init();
})();
