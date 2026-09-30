const API = "";

const $ = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  checkStatus();
});

function bindEvents() {
  const btn = $("vtLookupBtn");
  const input = $("vtQuery");
  const clearBtn = $("vtClearBtn");
  const typeSel = $("vtType");

  if (btn) btn.onclick = doLookup;
  if (clearBtn) clearBtn.onclick = reset;

  if (input) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") doLookup();
    });
  }
  if (typeSel) {
    typeSel.addEventListener("change", () => {
      const t = typeSel.value;
      input.placeholder =
        t === "ip" ? "e.g. 23.21.109.197" :
        t === "url" ? "e.g. https://apple.my-cloud-mail.com/…" :
        t === "domain" ? "e.g. my-cloud-mail.com" :
        "SHA-256 file hash";
    });
  }
}

async function checkStatus() {
  try {
    const res = await fetch(`${API}/api/health`);
    const data = await res.json();
    const el = $("vtStatus");
    if (data.virustotal_ready) {
      el.textContent = "VirusTotal ready";
      el.className = "status-chip ok";
    } else {
      el.textContent = "VirusTotal key missing";
      el.className = "status-chip bad";
    }
  } catch (err) {
    const el = $("vtStatus");
    el.textContent = "offline";
    el.className = "status-chip bad";
  }
}

function reset() {
  $("vtQuery").value = "";
  hide("vtResult");
  hide("vtError");
  hide("vtLoading");
}

async function doLookup() {
  const q = $("vtQuery").value.trim();
  const type = $("vtType").value;

  if (!q) {
    alert("Enter a value to look up.");
    return;
  }

  hide("vtResult");
  hide("vtError");
  show("vtLoading");

  try {
    const paramName =
      type === "ip" ? "ip" :
      type === "url" ? "url" :
      type === "domain" ? "domain" :
      "hash";

    const res = await fetch(`${API}/api/vt/${type}?${paramName}=${encodeURIComponent(q)}`);
    const data = await res.json();

    hide("vtLoading");

    if (!res.ok || data.error) {
      showError(data.error || `Lookup failed (${res.status})`);
      return;
    }
    render(data, type, q);
  } catch (err) {
    hide("vtLoading");
    showError(err.message);
  }
}

function showError(msg) {
  $("vtErrorText").textContent = "❌ " + msg;
  show("vtError");
}

function render(data, type, q) {
  const titleMap = { ip: "IP", url: "URL", domain: "Domain", hash: "File Hash" };
  $("vtResultTitle").textContent = `${titleMap[type]}: ${q}`;

  // Verdict
  const positives = data.positives ?? 0;
  const total = data.total_engines ?? data.total ?? 0;
  const verdictEl = $("vtVerdict");
  const ratio = total > 0 ? positives / total : 0;
  if (data.error) {
    verdictEl.textContent = "ERROR";
    verdictEl.className = "badge undetected";
  } else if (positives === 0 && total > 0) {
    verdictEl.textContent = "CLEAN";
    verdictEl.className = "badge safe";
  } else if (ratio < 0.05) {
    verdictEl.textContent = `${positives}/${total} flags`;
    verdictEl.className = "badge suspicious";
  } else {
    verdictEl.textContent = `${positives}/${total} flags`;
    verdictEl.className = "badge malicious";
  }

  // Summary
  const summaryRows = [];
  summaryRows.push(["Verdict", verdictText(positives, total)]);
  summaryRows.push(["Detections", `${positives} / ${total}`]);
  if (data.reputation !== undefined && data.reputation !== null)
    summaryRows.push(["Reputation", String(data.reputation)]);
  if (data.country) summaryRows.push(["Country", data.country]);
  if (data.as_owner) summaryRows.push(["AS Owner", data.as_owner]);
  if (data.asn) summaryRows.push(["ASN", String(data.asn)]);
  if (data.network) summaryRows.push(["Network", data.network]);
  if (data.regional_internet_registry)
    summaryRows.push(["RIR", data.regional_internet_registry]);
  if (data.continent) summaryRows.push(["Continent", data.continent]);
  if (data.registrar) summaryRows.push(["Registrar", data.registrar]);
  if (data.creation_date)
    summaryRows.push(["Created", fmtDate(data.creation_date)]);
  if (data.last_update_date)
    summaryRows.push(["Last Updated", fmtDate(data.last_update_date)]);
  if (data.last_analysis_date)
    summaryRows.push(["Last Analysis", fmtDate(data.last_analysis_date)]);
  if (Array.isArray(data.tags) && data.tags.length)
    summaryRows.push(["Tags", data.tags.join(", ")]);

  $("vtSummary").innerHTML = summaryRows
    .map(([k, v]) => `
      <div class="k">${escapeHtml(k)}</div>
      <div class="v">${v}</div>
    `)
    .join("");

  // Engine stats
  const stats = data.stats || {};
  const statOrder = ["malicious", "suspicious", "harmless", "undetected"];
  const statHtml = statOrder
    .filter((k) => stats[k] !== undefined)
    .map((k) => {
      const cls =
        k === "malicious" ? "malicious" :
        k === "suspicious" ? "suspicious" :
        k === "harmless" ? "harmless" : "undetected";
      return `<div class="stat-chip ${cls}">
        <span class="label">${k}</span>
        <span class="count">${stats[k]}</span>
      </div>`;
    })
    .join("");
  $("vtStats").innerHTML = statHtml || `<p class="muted">No engine data.</p>`;

  // Details (type-specific)
  const detailRows = [];
  if (type === "ip" && data.raw) {
    const r = data.raw;
    if (r.whois) detailRows.push(["WHOIS", `<pre class="raw-pre small-pre">${escapeHtml(r.whois)}</pre>`]);
    if (r.jarm) detailRows.push(["JARM", escapeHtml(r.jarm)]);
  }
  if (type === "domain") {
    if (data.categories && Object.keys(data.categories).length) {
      const cats = Object.entries(data.categories)
        .map(([k, v]) => `${v} (${k})`)
        .join(", ");
      detailRows.push(["Categories", escapeHtml(cats)]);
    }
    if (Array.isArray(data.dns_records) && data.dns_records.length) {
      const dns = data.dns_records
        .map((d) => `${d.type || "?"} ${d.value || d.rdata || ""}`)
        .join("\n");
      detailRows.push(["DNS Records", `<pre class="raw-pre small-pre">${escapeHtml(dns)}</pre>`]);
    }
    if (data.whois) detailRows.push(["WHOIS", `<pre class="raw-pre small-pre">${escapeHtml(data.whois)}</pre>`]);
  }

  $("vtDetails").innerHTML = detailRows.length
    ? detailRows.map(([k, v]) => `
        <div class="k">${escapeHtml(k)}</div>
        <div class="v">${v}</div>
      `).join("")
    : `<p class="muted">No extra details available.</p>`;

  // Raw JSON
  $("vtRaw").textContent = JSON.stringify(data.raw || data, null, 2);

  show("vtResult");
}

function verdictText(positives, total) {
  if (!total) return `<span class="badge undetected">No data</span>`;
  if (positives === 0) return `<span class="badge safe">Clean</span>`;
  if (positives / total < 0.05) return `<span class="badge suspicious">Low risk</span>`;
  if (positives / total < 0.20) return `<span class="badge suspicious">Suspicious</span>`;
  return `<span class="badge malicious">Malicious</span>`;
}

function fmtDate(ts) {
  if (!ts) return "—";
  const ms = ts > 1e12 ? ts : ts * 1000;
  return new Date(ms).toLocaleString();
}

function show(id) { const el = $(id); if (el) el.classList.remove("hidden"); }
function hide(id) { const el = $(id); if (el) el.classList.add("hidden"); }

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}