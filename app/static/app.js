const SAMPLE = [
  "foo@",
  "jane.doe@gmial.com",
  "newsletter@mailinator.com",
  "person@example.invalid",
  "name@clearlist-no-such-domain-zz12345.com",
  "info@gmail.com",
].join("\n");

const VERDICTS = {
  send: ["Safe to send", "safe"],
  suppress: ["Do not send", "bad"],
  retry: ["Soft-bounce risk", "soft"],
  review: ["Needs review", "risk"],
};

const BOUNCE = {
  none: "No bounce signal",
  hard: "Hard bounce",
  soft: "Soft bounce",
  unknown: "Bounce unknown",
};

const state = {
  rows: [],
  filter: "all",
  query: "",
  running: false,
  abort: null,
  forceSmtp: false,
};

const input = document.querySelector("#input");
const count = document.querySelector("#count");
const verifyBtn = document.querySelector("#verify");
const stopBtn = document.querySelector("#stop");
const permit = document.querySelector("#permit");
const banner = document.querySelector("#banner");
const bannerText = document.querySelector("#banner-text");
const forceBtn = document.querySelector("#force-smtp");
const results = document.querySelector("#results");
const list = document.querySelector("#list");
const empty = document.querySelector("#empty");
const progress = document.querySelector("#progress");
const bar = document.querySelector("#bar");
const progressLabel = document.querySelector("#progress-label");
const search = document.querySelector("#search");
const smtpBox = document.querySelector("#opt-smtp");
const catchBox = document.querySelector("#opt-catch");
const helo = document.querySelector("#helo");
const mailFrom = document.querySelector("#mailfrom");
const fileInput = document.querySelector("#file");
const composer = document.querySelector("#composer");

permit.checked = sessionStorage.getItem("clearlist-permit") === "1";
helo.value = localStorage.getItem("clearlist-helo") || "";
mailFrom.value = localStorage.getItem("clearlist-mailfrom") || "";
smtpBox.checked = localStorage.getItem("clearlist-smtp") !== "0";
catchBox.checked = localStorage.getItem("clearlist-catch") !== "0";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

function parseAddresses(raw) {
  const skip = new Set([
    "email",
    "e-mail",
    "emails",
    "email address",
    "mail",
    "address",
    "name",
    "first name",
    "last name",
  ]);
  const text = raw.replace(/[\u200b\u200c\u200d\ufeff]/g, "");
  const seen = new Set();
  const emails = [];
  let dupes = 0;

  function push(token) {
    const value = token.trim();
    if (!value) return;
    const key = value.toLowerCase();
    if (seen.has(key)) {
      dupes += 1;
      return;
    }
    seen.add(key);
    emails.push(value);
  }

  for (let piece of text.split(/[\s,;|]+/)) {
    piece = piece.replace(/^mailto:/i, "").replace(/^["'<([]+/, "").replace(/[>"')\]]+$/, "").trim();
    if (!piece || skip.has(piece.toLowerCase())) continue;
    if (piece.includes("@") || piece.includes(".")) push(piece);
  }

  if (!emails.length) {
    for (const line of text.split(/\r?\n/)) {
      const value = line.trim();
      if (value && !skip.has(value.toLowerCase())) push(value);
    }
  }
  return { emails, dupes };
}

function syncComposer() {
  const { emails, dupes } = parseAddresses(input.value);
  const tooMany = emails.length > 5000;
  if (!permit.checked) count.textContent = "Confirm you are allowed to verify this list.";
  else if (!emails.length) count.textContent = "Add at least one address.";
  else if (tooMany) count.textContent = "This check runs up to 5,000 addresses at a time. Split the file.";
  else if (dupes) count.textContent = `${emails.length} addresses, ${dupes} duplicates removed.`;
  else count.textContent = emails.length === 1 ? "1 address" : `${emails.length} addresses`;
  verifyBtn.disabled = state.running || !permit.checked || !emails.length || tooMany;
  verifyBtn.textContent = state.running ? "Checking..." : "Verify list";
  stopBtn.hidden = !state.running;
}

function showBanner(text, kind) {
  banner.hidden = !text;
  banner.classList.toggle("bad", kind === "bad");
  bannerText.textContent = text || "";
}

function errorMessage(payload, status) {
  if (!payload) return `Verification failed (${status}).`;
  if (typeof payload.detail === "string") return payload.detail;
  if (Array.isArray(payload.detail)) {
    return payload.detail.map((item) => item.msg || "Invalid request").join(" ");
  }
  return `Verification failed (${status}).`;
}

function tally(rows) {
  const totals = { all: rows.length, send: 0, suppress: 0, retry: 0, review: 0 };
  for (const row of rows) totals[row.action] = (totals[row.action] || 0) + 1;
  return totals;
}

function updateStats() {
  const totals = tally(state.rows);
  for (const key of Object.keys(totals)) {
    const node = document.querySelector(`[data-count="${key}"]`);
    if (node) node.textContent = String(totals[key]);
  }
  document.querySelectorAll("[data-download]").forEach((button) => {
    const kind = button.dataset.download;
    button.disabled = kind === "csv" ? state.rows.length === 0 : !totals[kind];
  });
}

function matches(row) {
  if (state.filter !== "all" && row.action !== state.filter) return false;
  const query = state.query.trim().toLowerCase();
  if (!query) return true;
  const risks = (row.risks || []).map((item) => `${item.label} ${item.detail}`).join(" ");
  return `${row.input} ${row.email} ${row.summary} ${risks}`.toLowerCase().includes(query);
}

function verdictFor(row) {
  if (row.action === "review" && row.status === "unknown") return ["Not confirmed", "unknown"];
  return VERDICTS[row.action] || ["Needs review", "risk"];
}

function rowCard(row) {
  const [label, tone] = verdictFor(row);
  const card = el("article", `result ${tone}`);
  const top = el("div", "result-top");
  top.append(el("span", `pill ${tone}`, label));
  top.append(el("span", "bounce", BOUNCE[row.bounce] || row.bounce));
  const score = el("span", "score", `Score ${row.score}`);
  score.title = "How likely this address is to accept mail without bouncing. Not inbox placement.";
  top.append(score);
  card.append(top);
  card.append(el("p", "addr", row.email || row.input));
  if (row.email && row.input && row.email !== row.input.trim()) {
    card.append(el("p", "checked-as", `From your list: ${row.input.trim()}`));
  }
  card.append(el("p", "why", row.summary));
  if (row.suggestion) card.append(el("p", "suggestion", `Suggested: ${row.suggestion}`));

  const chips = el("div", "chips");
  for (const item of row.risks || []) {
    chips.append(el("span", `chip ${item.severity || "info"}`, item.label));
  }
  if (chips.childNodes.length) card.append(chips);

  const toggle = el("button", "toggle", "Details");
  toggle.type = "button";
  toggle.setAttribute("aria-expanded", "false");
  const detail = el("div", "detail");
  detail.hidden = true;
  detail.append(detailList(row));
  toggle.addEventListener("click", () => {
    detail.hidden = !detail.hidden;
    toggle.setAttribute("aria-expanded", String(!detail.hidden));
    toggle.textContent = detail.hidden ? "Details" : "Hide details";
  });
  card.append(toggle, detail);
  return card;
}

function detailList(row) {
  const wrap = document.createElement("div");
  const dl = document.createElement("dl");
  const checks = row.checks || {};
  const rows = [
    ["Syntax", checks.syntax?.detail],
    ["DNS", checks.dns?.detail],
    ["MX", mxLine(checks.mx)],
    ["SMTP", checks.smtp?.detail],
    ["Catch-all", catchLine(checks.smtp?.catch_all)],
  ];
  for (const [name, value] of rows) {
    dl.append(el("dt", "", name), el("dd", "", value || "Not checked."));
  }
  wrap.append(dl);
  if ((row.risks || []).length) {
    const ul = document.createElement("ul");
    for (const item of row.risks) ul.append(el("li", "", `${item.label}: ${item.detail}`));
    wrap.append(ul);
  }
  return wrap;
}

function mxLine(mx) {
  if (!mx) return "Not checked.";
  const hosts = (mx.hosts || []).slice(0, 3).join(", ");
  return hosts ? `${mx.detail} Hosts: ${hosts}.` : mx.detail;
}

function catchLine(value) {
  if (value === true) return "Yes. The server accepted a made-up address.";
  if (value === false) return "No. The server rejected a made-up address.";
  return "Not tested.";
}

function renderList() {
  const visible = state.rows.filter(matches);
  list.replaceChildren();
  const fragment = document.createDocumentFragment();
  for (const row of visible) fragment.append(rowCard(row));
  list.append(fragment);
  empty.hidden = visible.length !== 0;
}

function addRows(rows) {
  state.rows.push(...rows);
  updateStats();
  if (state.filter === "all" && !state.query.trim()) {
    const fragment = document.createDocumentFragment();
    for (const row of rows) fragment.append(rowCard(row));
    list.append(fragment);
    empty.hidden = state.rows.length !== 0;
  } else {
    renderList();
  }
}

function csvCell(value) {
  let text = String(value ?? "");
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  if (/[",\n]/.test(text)) return `"${text.replaceAll('"', '""')}"`;
  return text;
}

function download(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function exportRows(kind) {
  if (kind === "csv") {
    const headers = ["input", "email", "status", "action", "bounce", "score", "summary", "suggestion", "mx", "smtp_state", "smtp_code", "smtp_detail", "risks"];
    const lines = [headers.join(",")];
    for (const row of state.rows) {
      const values = [
        row.input,
        row.email,
        row.status,
        row.action,
        row.bounce,
        row.score,
        row.summary,
        row.suggestion || "",
        (row.checks?.mx?.hosts || []).join(" "),
        row.checks?.smtp?.state || "",
        row.checks?.smtp?.code ?? "",
        row.checks?.smtp?.detail || "",
        (row.risks || []).map((item) => item.label).join("; "),
      ];
      lines.push(values.map(csvCell).join(","));
    }
    download("clearlist-report.csv", lines.join("\n"), "text/csv");
    return;
  }
  const lines = state.rows.filter((row) => row.action === kind).map((row) => row.email || row.input);
  download(`clearlist-${kind}.txt`, lines.join("\n"), "text/plain");
}

async function runVerification() {
  const { emails } = parseAddresses(input.value);
  if (!permit.checked || !emails.length || emails.length > 5000 || state.running) return;
  const sender = mailFrom.value.trim();
  if (sender && !sender.includes("@")) {
    showBanner("MAIL FROM should be a full email address, or left empty.", "bad");
    return;
  }

  state.running = true;
  state.rows = [];
  list.replaceChildren();
  updateStats();
  results.hidden = false;
  empty.hidden = true;
  progress.hidden = false;
  showBanner("");
  forceBtn.hidden = true;
  syncComposer();

  const controller = new AbortController();
  state.abort = controller;
  let cursor = 0;
  let chunkSize = smtpBox.checked ? 8 : 40;
  let network = "disabled";

  try {
    while (cursor < emails.length) {
      const chunk = emails.slice(cursor, cursor + chunkSize);
      progressLabel.textContent = `Checking ${cursor + 1} to ${cursor + chunk.length} of ${emails.length}`;
      bar.style.width = `${Math.round((cursor / emails.length) * 100)}%`;
      const response = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
        body: JSON.stringify({
          emails: chunk,
          smtp: smtpBox.checked,
          catch_all: catchBox.checked,
          helo: helo.value.trim(),
          mail_from: sender,
          force_smtp: state.forceSmtp,
        }),
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) throw new Error(errorMessage(payload, response.status));
      network = payload.smtp_network || network;
      if (network === "blocked" && !state.forceSmtp) {
        showBanner(
          "This network blocks outbound port 25, so mailbox SMTP checks were skipped. Syntax, DNS, MX, and risk checks still ran. Addresses that fail those checks are unsafe to send. Addresses that pass are not fully confirmed.",
        );
        forceBtn.hidden = false;
        chunkSize = 40;
      }
      addRows(payload.results || []);
      cursor += chunk.length;
    }
    bar.style.width = "100%";
    const totals = tally(state.rows);
    progressLabel.textContent = `${totals.send} safe to send, ${totals.suppress} to suppress, ${totals.retry} to retry, ${totals.review} to review.`;
    if (network === "open" || network === "forced") showBanner("");
  } catch (error) {
    if (error.name === "AbortError") {
      showBanner("Stopped. Partial results are kept below.");
      progressLabel.textContent = "Stopped.";
    } else {
      showBanner(error.message || "Verification failed.", "bad");
    }
  } finally {
    state.running = false;
    state.abort = null;
    syncComposer();
  }
}

input.addEventListener("input", syncComposer);
permit.addEventListener("change", () => {
  sessionStorage.setItem("clearlist-permit", permit.checked ? "1" : "0");
  syncComposer();
});
helo.addEventListener("change", () => localStorage.setItem("clearlist-helo", helo.value.trim()));
mailFrom.addEventListener("change", () => localStorage.setItem("clearlist-mailfrom", mailFrom.value.trim()));
smtpBox.addEventListener("change", () => localStorage.setItem("clearlist-smtp", smtpBox.checked ? "1" : "0"));
catchBox.addEventListener("change", () => localStorage.setItem("clearlist-catch", catchBox.checked ? "1" : "0"));

document.querySelector("#sample").addEventListener("click", () => {
  if (input.value.trim() && !window.confirm("Replace the current list with examples?")) return;
  input.value = SAMPLE;
  syncComposer();
});
document.querySelector("#upload").addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", async () => {
  const file = fileInput.files && fileInput.files[0];
  fileInput.value = "";
  if (!file) return;
  if (input.value.trim() && !window.confirm("Replace the current list with this file?")) return;
  input.value = await file.text();
  syncComposer();
});

composer.addEventListener("dragover", (event) => {
  event.preventDefault();
  composer.classList.add("drag");
});
composer.addEventListener("dragleave", () => composer.classList.remove("drag"));
composer.addEventListener("drop", async (event) => {
  event.preventDefault();
  composer.classList.remove("drag");
  const file = event.dataTransfer?.files?.[0];
  if (file) input.value = await file.text();
  else input.value = event.dataTransfer?.getData("text") || input.value;
  syncComposer();
});

verifyBtn.addEventListener("click", () => {
  state.forceSmtp = false;
  runVerification();
});
forceBtn.addEventListener("click", () => {
  state.forceSmtp = true;
  showBanner("Trying SMTP even though port 25 looked blocked. This can be slow.");
  runVerification();
});
stopBtn.addEventListener("click", () => state.abort?.abort());
input.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    event.preventDefault();
    state.forceSmtp = false;
    runVerification();
  }
});

document.querySelectorAll("[data-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    state.filter = button.dataset.filter;
    document.querySelectorAll("[data-filter]").forEach((item) => {
      item.classList.toggle("active", item === button);
    });
    renderList();
  });
});
search.addEventListener("input", () => {
  state.query = search.value;
  renderList();
});
document.querySelectorAll("[data-download]").forEach((button) => {
  button.addEventListener("click", () => exportRows(button.dataset.download));
});

fetch("/api/health")
  .then((response) => response.json())
  .then((data) => {
    if (data.helo) helo.placeholder = data.helo;
  })
  .catch(() => {});

syncComposer();
