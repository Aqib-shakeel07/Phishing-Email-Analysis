const API = "";

const $ = (id) => document.getElementById(id);

let allItems = [];

document.addEventListener("DOMContentLoaded", () => {
  $("year").textContent = new Date().getFullYear();
  $("refreshBtn").addEventListener("click", loadAll);
  $("searchInput").addEventListener("input", applyFilters);
  $("verdictFilter").addEventListener("change", applyFilters);
  loadAll();
});

async function loadAll() {
  await Promise.all([loadStats(), loadHistory()]);
}

async function loadStats() {
  try {
    const res = await fetch(`${API}/api/stats`);
    const data = await res.json();
    $("statTotal").textContent = data.total ?? 0;
    $("statSafe").textContent = data.safe ?? 0;
    $("statSuspicious").textContent = data.suspicious ?? 0;
    $("statPhishing").textContent = data.phishing ?? 0;
  } catch (err) {
    console.error("stats failed", err);
  }
}

async function loadHistory() {
  const tbody = $("historyBody");
  tbody.innerHTML = `<tr><td colspan="7" class="muted">Loading...</td></tr>`;
  try {
    const res = await fetch(`${API}/api/analyses?limit=200`);
    const data = await res.json();
    allItems = data.items || [];
    applyFilters();
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">Failed to load.</td></tr>`;
  }
}

function applyFilters() {
  const q = $("searchInput").value.trim().toLowerCase();
  const verdict = $("verdictFilter").value;

  const filtered = allItems.filter((it) => {
    if (verdict && it.verdict !== verdict) return false;
    if (!q) return true;
    const hay = `${it.sender || ""} ${it.subject || ""} ${it.sender_domain || ""}`.toLowerCase();
    return hay.includes(q);
  });

  renderTable(filtered);
}

function renderTable(items) {
  const tbody = $("historyBody");
  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">No analyses found.</td></tr>`;
    return;
  }

  tbody.innerHTML = items
    .map((it) => {
      const cls = (it.verdict || "Unknown").toLowerCase();
      const date = it.created_at ? new Date(it.created_at).toLocaleString() : "-";
      return `
        <tr>
          <td>#${it.id}</td>
          <td>${escapeHtml(date)}</td>
          <td>${escapeHtml(it.sender || "-")}</td>
          <td class="subject-cell" title="${escapeHtml(it.subject || "")}">${escapeHtml(it.subject || "(no subject)")}</td>
          <td>${it.final_score ?? 0}</td>
          <td><span class="badge ${cls}">${escapeHtml(it.verdict || "Unknown")}</span></td>
          <td>
            <button class="icon-btn" data-action="json" data-id="${it.id}">JSON</button>
            <button class="icon-btn" data-action="pdf" data-id="${it.id}">PDF</button>
            <button class="icon-btn" data-action="delete" data-id="${it.id}">🗑</button>
          </td>
        </tr>`;
    })
    .join("");

  tbody.querySelectorAll(".icon-btn").forEach((btn) => {
    btn.addEventListener("click", onRowAction);
  });
}

async function onRowAction(e) {
  const action = e.currentTarget.dataset.action;
  const id = e.currentTarget.dataset.id;

  if (action === "json") {
    window.open(`/api/analyses/${id}/report?format=json`, "_blank");
  } else if (action === "pdf") {
    window.open(`/api/analyses/${id}/report?format=pdf`, "_blank");
  } else if (action === "delete") {
    if (!confirm(`Delete analysis #${id}?`)) return;
    await fetch(`${API}/api/analyses/${id}`, { method: "DELETE" });
    loadAll();
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}