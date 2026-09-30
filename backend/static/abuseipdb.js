const API = "";

const $ = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  checkStatus();
});

function bindEvents() {
  const btn = $("abuseLookupBtn");
  const input = $("abuseQuery");
  const clearBtn = $("abuseClearBtn");

  if (btn) btn.onclick = doLookup;
  if (clearBtn) clearBtn.onclick = reset;

  if (input) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") doLookup();
    });
  }
}

async function checkStatus() {
  try {
    const res = await fetch(`${API}/api/health`);
    const data = await res.json();
    const el = $("abuseStatus");
    if (data.abuseipdb_ready) {
      el.textContent = "AbuseIPDB ready";
      el.className = "status-chip ok";
    } else {
      el.textContent = "AbuseIPDB key missing";
      el.className = "status-chip bad";
    }
  } catch (err) {
    const el = $("abuseStatus");
    el.textContent = "offline";
    el.className = "status-chip bad";
  }
}

function reset() {
  $("abuseQuery").value = "";
  hide("abuseResult");
  hide("abuseError");
  hide("abuseLoading");
}

async function doLookup() {
  const q = $("abuseQuery").value.trim();
  const days = $("abuseDays").value;

  if (!q) {
    alert("Enter an IP address.");
    return;
  }

  hide("abuseResult");
  hide("abuseError");
  show("abuseLoading");

  try {
    const res = await fetch(
      `${API}/api/abuse/ip?ip=${encodeURIComponent(q)}&days=${days}`
    );
    const data = await res.json();

    hide("abuseLoading");

    if (!res.ok || data.error) {
      showError(data.error || `Lookup failed (${res.status})`);
      return;
    }
    render(data, q);
  } catch (err) {
    hide("abuseLoading");
    showError(err.message);
  }
}

function showError(msg) {
  $("abuseErrorText").textContent = "❌ " + msg;
  show("abuseError");
}

function render(data, q) {
  $("abuseTitle").textContent = `IP: ${q}`;

  const score = data.abuse_confidence_score ?? 0;
  const verdictEl = $("abuseVerdict");
  if (score === 0) {
    verdictEl.textContent = "CLEAN";
    verdictEl.className = "badge safe";
  } else if (score < 25) {
    verdictEl.textContent = `SCORE ${score}%`;
    verdictEl.className = "badge suspicious";
  } else if (score < 75) {
    verdictEl.textContent = `SCORE ${score}%`;
    verdictEl.className = "badge suspicious";
  } else {
    verdictEl.textContent = `SCORE ${score}%`;
    verdictEl.className = "badge malicious";
  }

  // Summary grid
  const rows = [
    ["IP", escapeHtml(data.ip || q)],
    ["Public", data.is_public ? "Yes" : "No"],
    ["Whitelisted", data.is_whitelisted ? "Yes" : "No"],
    ["Tor Exit", data.is_tor ? "Yes" : "No"],
    ["Abuse Confidence", `<span class="badge ${score >= 75 ? "malicious" : score >= 25 ? "suspicious" : "safe"}">${score}%</span>`],
    ["Total Reports", String(data.total_reports ?? 0)],
    ["Distinct Users", String(data.num_distinct_users ?? 0)],
    ["Last Reported", data.last_reported_at ? escapeHtml(data.last_reported_at) : "—"],
    ["Country", data.country_name ? `${escapeHtml(data.country_name)} (${escapeHtml(data.country_code || "")})` : "—"],
    ["ISP", escapeHtml(data.isp || "—")],
    ["Usage Type", escapeHtml(data.usage_type || "—")],
    ["Domain", escapeHtml(data.domain || "—")],
    ["Hostnames", (data.hostnames && data.hostnames.length) ? escapeHtml(data.hostnames.join(", ")) : "—"],
  ];
  $("abuseSummary").innerHTML = rows
    .map(([k, v]) => `<div class="k">${escapeHtml(k)}</div><div class="v">${v}</div>`)
    .join("");

  // Confidence bar
  const fill = $("abuseConfidenceFill");
  fill.style.width = `${score}%`;
  fill.className = "confidence-fill";
  if (score >= 75) fill.classList.add("high");
  else if (score >= 25) fill.classList.add("mid");
  $("abuseConfidenceValue").textContent = `${score}%`;

  // Reports
  const reports = data.reports || [];
  if (!reports.length) {
    $("abuseReports").innerHTML = `<p class="muted">No reports in this period.</p>`;
  } else {
    $("abuseReports").innerHTML = reports.map((r) => {
      const cats = r.categories && r.categories.length
        ? `<div class="rc-cats">${r.categories.map((c) => `<span>cat ${c}</span>`).join("")}</div>`
        : "";
      return `<div class="report-card">
        <div class="rc-head">
          <span class="badge ${r.categories?.includes(14) || r.categories?.includes(15) ? "malicious" : "suspicious"}">
            ${escapeHtml(String(r.reporterCountryCode || "?"))}
          </span>
          <span class="rc-date">${escapeHtml(r.reportedAt || "")}</span>
        </div>
        <div class="rc-comment">${escapeHtml(r.comment || "(no comment)")}</div>
        ${cats}
      </div>`;
    }).join("");
  }

  // Raw JSON
  $("abuseRaw").textContent = JSON.stringify(data.raw || data, null, 2);

  show("abuseResult");
}

function show(id) { const el = $(id); if (el) el.classList.remove("hidden"); }
function hide(id) { const el = $(id); if (el) el.classList.add("hidden"); }

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}