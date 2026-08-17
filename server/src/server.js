const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const Busboy = require("busboy");
const express = require("express");

const PORT = Number(process.env.PORT || 8080);
const ROOT = path.resolve(__dirname, "..");
const REQUESTED_STORAGE_DIR = process.env.STORAGE_DIR || ROOT;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const DEVICE_TOKEN = process.env.DEVICE_TOKEN || "";
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || "";
const AUTH_WINDOW_MS = Number(process.env.AUTH_WINDOW_MS || 10 * 60 * 1000);
const ADMIN_MAX_AUTH_FAILURES = Number(process.env.ADMIN_MAX_AUTH_FAILURES || 10);
const DEVICE_MAX_AUTH_FAILURES = Number(process.env.DEVICE_MAX_AUTH_FAILURES || 30);
const ADMIN_RATE_LIMIT = Number(process.env.ADMIN_RATE_LIMIT || 120);
const DEVICE_RATE_LIMIT = Number(process.env.DEVICE_RATE_LIMIT || 600);
const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_BYTES || 1024 * 1024 * 1024);
const MAX_JSON_BYTES = process.env.MAX_JSON_BYTES || "256kb";

const authFailures = new Map();
const rateBuckets = new Map();

function prepareStorageDir(requestedDir) {
  const candidates = [
    requestedDir,
    path.join(os.tmpdir(), "adcast-player")
  ];
  for (const candidate of candidates) {
    try {
      fs.mkdirSync(path.join(candidate, "data"), { recursive: true });
      fs.mkdirSync(path.join(candidate, "uploads"), { recursive: true });
      return candidate;
    } catch (err) {
      console.warn(`Storage not writable: ${candidate} (${err.code || err.message})`);
    }
  }
  throw new Error("No writable storage directory available");
}

const STORAGE_DIR = prepareStorageDir(REQUESTED_STORAGE_DIR);
const DATA_DIR = path.join(STORAGE_DIR, "data");
const UPLOADS_DIR = path.join(STORAGE_DIR, "uploads");
const STATE_FILE = path.join(DATA_DIR, "state.json");

function initialState() {
  return {
    manifest: null,
    devices: {},
    command: null,
    events: []
  };
}

function loadState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
  } catch {
    return initialState();
  }
}

function saveState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

function addEvent(state, event) {
  state.events.unshift({ time: new Date().toISOString(), ...event });
  state.events = state.events.slice(0, 100);
}

function publicBaseUrl(req) {
  return PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`;
}

function authorizedDevice(req) {
  if (!DEVICE_TOKEN) {
    return true;
  }
  const header = req.get("x-device-token") || "";
  return header === DEVICE_TOKEN;
}

function clientIp(req) {
  const forwarded = req.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }
  return req.ip || req.socket.remoteAddress || "unknown";
}

function failureKey(kind, req) {
  return `${kind}:${clientIp(req)}`;
}

function isBlocked(kind, req, maxFailures) {
  const key = failureKey(kind, req);
  const entry = authFailures.get(key);
  if (!entry) {
    return false;
  }
  if (Date.now() - entry.firstFailureAt > AUTH_WINDOW_MS) {
    authFailures.delete(key);
    return false;
  }
  return entry.count >= maxFailures;
}

function recordAuthFailure(kind, req) {
  const key = failureKey(kind, req);
  const now = Date.now();
  const entry = authFailures.get(key);
  if (!entry || now - entry.firstFailureAt > AUTH_WINDOW_MS) {
    authFailures.set(key, { count: 1, firstFailureAt: now });
    return;
  }
  entry.count += 1;
}

function clearAuthFailure(kind, req) {
  authFailures.delete(failureKey(kind, req));
}

function securityHeaders(req, res, next) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cache-Control", "no-store");
  next();
}

function rateLimit(kind, maxRequests) {
  return (req, res, next) => {
    const key = `${kind}:${clientIp(req)}`;
    const now = Date.now();
    const entry = rateBuckets.get(key);
    if (!entry || now - entry.startedAt > AUTH_WINDOW_MS) {
      rateBuckets.set(key, { count: 1, startedAt: now });
      next();
      return;
    }
    entry.count += 1;
    if (entry.count > maxRequests) {
      res.status(429).send("too many requests");
      return;
    }
    next();
  };
}

function hasSuspiciousText(value) {
  if (typeof value !== "string") {
    return false;
  }
  const text = value.toLowerCase();
  return [
    "../",
    "..\\",
    "<script",
    "%3cscript",
    " union select ",
    " drop table ",
    " information_schema",
    " or 1=1",
    "' or '1'='1",
    "\" or \"1\"=\"1",
    ";--",
    "/*",
    "*/"
  ].some(pattern => text.includes(pattern));
}

function blockSuspiciousRequest(req, res, next) {
  if (hasSuspiciousText(req.originalUrl)) {
    res.status(400).send("bad request");
    return;
  }
  for (const value of Object.values(req.query || {})) {
    if (hasSuspiciousText(String(value))) {
      res.status(400).send("bad request");
      return;
    }
  }
  if (req.is("application/json") && req.body) {
    const bodyText = JSON.stringify(req.body);
    if (bodyText.length > 0 && hasSuspiciousText(bodyText)) {
      res.status(400).send("bad request");
      return;
    }
  }
  next();
}

function requireDevice(req, res, next) {
  if (isBlocked("device", req, DEVICE_MAX_AUTH_FAILURES)) {
    res.status(429).json({ error: "too_many_device_auth_failures" });
    return;
  }
  if (!authorizedDevice(req)) {
    recordAuthFailure("device", req);
    res.status(401).json({ error: "unauthorized_device" });
    return;
  }
  clearAuthFailure("device", req);
  next();
}

function requireAdmin(req, res, next) {
  if (!ADMIN_PASSWORD) {
    next();
    return;
  }
  if (isBlocked("admin", req, ADMIN_MAX_AUTH_FAILURES)) {
    res.status(429).send("too many auth failures");
    return;
  }
  const auth = req.get("authorization") || "";
  if (!auth.startsWith("Basic ")) {
    recordAuthFailure("admin", req);
    res.set("WWW-Authenticate", "Basic realm=\"AdCast Player\"");
    res.status(401).send("auth required");
    return;
  }
  const raw = Buffer.from(auth.slice(6), "base64").toString("utf8");
  const idx = raw.indexOf(":");
  const user = idx >= 0 ? raw.slice(0, idx) : "";
  const pass = idx >= 0 ? raw.slice(idx + 1) : "";
  if (user !== ADMIN_USER || pass !== ADMIN_PASSWORD) {
    recordAuthFailure("admin", req);
    res.set("WWW-Authenticate", "Basic realm=\"AdCast Player\"");
    res.status(401).send("auth required");
    return;
  }
  clearAuthFailure("admin", req);
  next();
}

function withDeviceToken(urlPath) {
  return urlPath;
}

function localIps() {
  const nets = os.networkInterfaces();
  const ips = [];
  for (const items of Object.values(nets)) {
    for (const item of items || []) {
      if (item.family === "IPv4" && !item.internal) {
        ips.push(item.address);
      }
    }
  }
  return ips;
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", chunk => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString("pt-BR") : "nenhum";
}

function formatBytes(bytes) {
  if (!Number.isFinite(Number(bytes))) {
    return "nenhum";
  }
  const units = ["B", "KB", "MB", "GB"];
  let size = Number(bytes);
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function isDeviceOnline(device) {
  if (!device.last_contact) {
    return false;
  }
  return Date.now() - new Date(device.last_contact).getTime() < 90000;
}

function html(state, requestedView = "dashboard") {
  const views = new Set(["dashboard", "devices", "publish", "server", "events"]);
  const activeView = views.has(requestedView) ? requestedView : "dashboard";
  const manifest = state.manifest;
  const devices = Object.values(state.devices || {})
    .sort((a, b) => new Date(b.last_contact || 0) - new Date(a.last_contact || 0));
  const latestDevice = devices[0] || {};
  const lastHealth = latestDevice.last_health_check || null;
  const pendingCommand = state.command && !state.command.completed_at ? state.command : null;
  const ips = localIps();
  const onlineCount = devices.filter(isDeviceOnline).length;
  const updatingCount = devices.filter(device => !["IDLE", "SUCCESS", "FAILED", undefined, null].includes(device.update_state)).length;
  const errorCount = devices.filter(device => device.last_error || device.update_state === "FAILED").length;
  const offlineCount = Math.max(devices.length - onlineCount, 0);
  const nextVersion = manifest ? manifest.version + 1 : 1;
  const latestHealthText = lastHealth
    ? `${formatDate(lastHealth.time)} | playback=${lastHealth.playback ? "sim" : "nao"} | posicao=${lastHealth.position_ms || 0} ms | estado=${escapeHtml(lastHealth.update_state || "desconhecido")}`
    : "nenhuma";
  const deviceRows = devices.length
    ? devices.map(device => {
      const online = isDeviceOnline(device);
      return `<tr>
        <td><strong>${escapeHtml(device.device_id || "unknown")}</strong></td>
        <td><span class="pill ${online ? "good" : "danger"}">${online ? "ONLINE" : "OFFLINE"}</span></td>
        <td>${escapeHtml(device.version ?? "0")}</td>
        <td>${device.playback ? "RODANDO" : "nao confirmado"}</td>
        <td>${escapeHtml(device.position_ms ?? 0)} ms</td>
        <td>${escapeHtml(device.update_state || "desconhecido")}</td>
        <td>${formatDate(device.last_contact)}</td>
        <td>${escapeHtml(device.last_error || "nenhum")}</td>
      </tr>`;
    }).join("")
    : `<tr><td colspan="8" class="empty">Nenhuma TV conectou ainda.</td></tr>`;
  const eventRows = (state.events || []).length
    ? state.events.map(e => `<tr>
      <td>${formatDate(e.time)}</td>
      <td>${escapeHtml(e.device_id || "")}</td>
      <td>${escapeHtml(e.update_state || "")}</td>
      <td>${escapeHtml(e.event || "")}</td>
      <td>${escapeHtml(e.version ?? "")}</td>
      <td>${escapeHtml(e.last_error || "")}</td>
    </tr>`).join("")
    : `<tr><td colspan="6" class="empty">Nenhum evento registrado ainda.</td></tr>`;
  const navItem = (view, label) => `<a class="${activeView === view ? "active" : ""}" href="/?view=${view}">${label}</a>`;
  const pageMeta = {
    dashboard: ["Dashboard", "Status atual dos displays instalados."],
    devices: ["TVs", "Controle individual dos players instalados."],
    publish: ["Publicar video", "Envie uma nova campanha MP4 para as TVs."],
    server: ["Servidor", "Configuracoes operacionais e manifest publicado."],
    events: ["Eventos", "Historico recente recebido dos dispositivos."]
  };
  const dashboardContent = `
    <section>
      <div class="grid">
        <div class="metric"><span>TVs cadastradas</span><strong>${devices.length}</strong></div>
        <div class="metric"><span>Online</span><strong class="good">${onlineCount}</strong></div>
        <div class="metric"><span>Offline</span><strong class="${offlineCount ? "danger" : ""}">${offlineCount}</strong></div>
        <div class="metric"><span>Atualizando</span><strong class="${updatingCount ? "warn" : ""}">${updatingCount}</strong></div>
      </div>
      <div class="split">
        <div>
          <h3>TV mais recente</h3>
          <dl>
            <dt>Dispositivo</dt><dd>${escapeHtml(latestDevice.device_id || "nenhum")}</dd>
            <dt>Status</dt><dd><span class="pill ${isDeviceOnline(latestDevice) ? "good" : "danger"}">${isDeviceOnline(latestDevice) ? "ONLINE" : "OFFLINE"}</span></dd>
            <dt>Ultimo contato</dt><dd>${formatDate(latestDevice.last_contact)}</dd>
            <dt>Versao instalada</dt><dd>${escapeHtml(latestDevice.version ?? "desconhecida")}</dd>
            <dt>Playback</dt><dd>${latestDevice.playback ? "RODANDO" : "nao confirmado"}</dd>
            <dt>Posicao</dt><dd>${escapeHtml(latestDevice.position_ms ?? 0)} ms</dd>
            <dt>Estado update</dt><dd>${escapeHtml(latestDevice.update_state || "desconhecido")}</dd>
            <dt>Ultimo erro</dt><dd>${escapeHtml(latestDevice.last_error || "nenhum")}</dd>
          </dl>
        </div>
        <div>
          <h3>Verificacao remota</h3>
          <dl>
            <dt>Pedido atual</dt><dd>${pendingCommand ? `aguardando resposta (${escapeHtml(pendingCommand.id)})` : "nenhum"}</dd>
            <dt>Ultima verificacao</dt><dd>${latestHealthText}</dd>
            <dt>Erros ativos</dt><dd>${errorCount}</dd>
          </dl>
        </div>
      </div>
    </section>`;
  const devicesContent = `
    <section>
      <h3>TVs instaladas</h3>
      <div class="table-wrap">
        <table>
          <tr><th>Dispositivo</th><th>Status</th><th>Versao</th><th>Playback</th><th>Posicao</th><th>Update</th><th>Ultimo contato</th><th>Erro</th></tr>
          ${deviceRows}
        </table>
      </div>
    </section>`;
  const publishContent = `
    <section>
      <h3>Publicar video</h3>
      <form action="/api/publish" method="post" enctype="multipart/form-data">
        <label>Arquivo MP4</label>
        <input name="video" type="file" accept="video/mp4" required>
        <label>Versao</label>
        <input name="version" type="number" min="1" step="1" value="${nextVersion}" required>
        <button type="submit">PUBLICAR ATUALIZACAO</button>
      </form>
    </section>
    <section>
      <h3>Manifest publicado</h3>
      <dl>
        <dt>Versao</dt><dd>${manifest ? escapeHtml(manifest.version) : "nenhuma"}</dd>
        <dt>Arquivo</dt><dd>${manifest ? escapeHtml(manifest.filename) : "nenhum"}</dd>
        <dt>Original</dt><dd>${manifest ? escapeHtml(manifest.original_filename || manifest.filename) : "nenhum"}</dd>
        <dt>Tamanho</dt><dd>${manifest ? formatBytes(manifest.size) : "nenhum"}</dd>
        <dt>SHA-256</dt><dd>${manifest ? escapeHtml(manifest.sha256) : "nenhum"}</dd>
        <dt>URL</dt><dd>${manifest ? escapeHtml(manifest.download_url) : "nenhuma"}</dd>
        <dt>Publicado em</dt><dd>${manifest ? formatDate(manifest.published_at) : "nenhum"}</dd>
      </dl>
    </section>`;
  const serverContent = `
    <section>
      <h3>Servidor</h3>
      <dl>
        <dt>Porta</dt><dd>${PORT}</dd>
        <dt>Storage</dt><dd>${escapeHtml(STORAGE_DIR)}</dd>
        <dt>Modo internet</dt><dd>${escapeHtml(PUBLIC_BASE_URL ? PUBLIC_BASE_URL : "local/LAN")}</dd>
        <dt>Limite upload</dt><dd>${formatBytes(MAX_UPLOAD_BYTES)}</dd>
        <dt>Rate limit</dt><dd>admin=${ADMIN_RATE_LIMIT}/janela, device=${DEVICE_RATE_LIMIT}/janela, bloqueio=${Math.round(AUTH_WINDOW_MS / 60000)} min</dd>
        <dt>IPs deste PC</dt><dd><span class="server-list">${ips.map(ip => `<code>http://${escapeHtml(ip)}:${PORT}</code>`).join(" ") || "nenhum IP LAN encontrado"}</span></dd>
      </dl>
    </section>`;
  const eventsContent = `
    <section>
      <h3>Eventos recentes</h3>
      <div class="table-wrap">
        <table>
          <tr><th>Hora</th><th>Dispositivo</th><th>Estado</th><th>Evento</th><th>Versao</th><th>Erro</th></tr>
          ${eventRows}
        </table>
      </div>
    </section>`;
  const activeContent = {
    dashboard: dashboardContent,
    devices: devicesContent,
    publish: publishContent,
    server: serverContent,
    events: eventsContent
  }[activeView];

  return `<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AdCast Player</title>
  <style>
    :root {
      --bg: #eef2f5;
      --panel: #ffffff;
      --ink: #14202b;
      --muted: #647281;
      --line: #d8e0e7;
      --nav: #132633;
      --accent: #1769aa;
      --good: #087f3a;
      --warn: #a56a00;
      --danger: #b42318;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Arial, sans-serif; background: var(--bg); color: var(--ink); }
    .shell { display: grid; grid-template-columns: 248px minmax(0, 1fr); min-height: 100vh; }
    aside { position: sticky; top: 0; height: 100vh; padding: 22px 18px; background: var(--nav); color: white; }
    aside h1 { font-size: 20px; margin: 0 0 4px; }
    aside p { color: #b8c7d1; font-size: 13px; margin: 0 0 24px; }
    nav a { display: block; color: #dce7ee; text-decoration: none; padding: 10px 12px; border-radius: 6px; margin-bottom: 6px; font-weight: 700; }
    nav a:hover, nav a.active { background: rgba(255, 255, 255, 0.12); color: white; }
    main { padding: 28px; max-width: 1320px; width: 100%; }
    header { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin-bottom: 18px; }
    header h2 { font-size: 26px; margin: 0 0 4px; }
    header p { margin: 0; color: var(--muted); }
    section { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 18px; margin-bottom: 16px; }
    section h3 { font-size: 18px; margin: 0 0 14px; }
    label { display: block; font-weight: 700; margin: 12px 0 6px; }
    input, button { font: inherit; }
    input[type="number"], input[type="file"] { width: 100%; padding: 10px; border: 1px solid #b8c3cc; border-radius: 6px; background: white; }
    button { margin-top: 14px; padding: 10px 14px; border: 0; border-radius: 6px; background: var(--accent); color: white; font-weight: 700; cursor: pointer; }
    dl { display: grid; grid-template-columns: 150px 1fr; gap: 8px 14px; margin: 0; }
    dt { font-weight: 700; color: #405261; }
    dd { margin: 0; word-break: break-word; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px 8px; border-bottom: 1px solid #e4e8ec; text-align: left; font-size: 14px; vertical-align: top; }
    th { color: #435566; font-size: 12px; text-transform: uppercase; letter-spacing: 0; }
    code { background: #edf2f6; padding: 2px 5px; border-radius: 4px; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }
    .metric { background: #f8fafb; border: 1px solid var(--line); border-radius: 8px; padding: 14px; }
    .metric span { display: block; color: var(--muted); font-size: 13px; font-weight: 700; }
    .metric strong { display: block; font-size: 28px; margin-top: 6px; }
    .split { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(300px, 0.9fr); gap: 16px; }
    .pill { display: inline-block; min-width: 76px; text-align: center; padding: 4px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; }
    .good { color: var(--good); background: #e7f6ee; }
    .warn { color: var(--warn); background: #fff3da; }
    .danger { color: var(--danger); background: #fdebea; }
    .neutral { color: #405261; background: #edf2f6; }
    .empty { color: var(--muted); text-align: center; padding: 24px 8px; }
    .table-wrap { overflow-x: auto; }
    .server-list { display: flex; flex-wrap: wrap; gap: 6px; }
    .inline { display: inline; }
    .header-actions { min-width: 170px; text-align: right; }
    @media (max-width: 900px) {
      .shell { grid-template-columns: 1fr; }
      aside { position: static; height: auto; }
      nav { display: flex; flex-wrap: wrap; gap: 6px; }
      nav a { margin: 0; }
      main { padding: 18px; }
      header { display: block; }
      .grid, .split { grid-template-columns: 1fr; }
      dl { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
<div class="shell">
  <aside>
    <h1>AdCast Player</h1>
    <p>Painel operacional</p>
    <nav>
      ${navItem("dashboard", "Dashboard")}
      ${navItem("devices", "TVs")}
      ${navItem("publish", "Publicar video")}
      ${navItem("server", "Servidor")}
      ${navItem("events", "Eventos")}
    </nav>
  </aside>
  <main>
    <header>
      <div>
        <h2>${pageMeta[activeView][0]}</h2>
        <p>${pageMeta[activeView][1]}</p>
      </div>
      <div class="header-actions">
        ${activeView === "dashboard" || activeView === "devices" ? `<form class="inline" action="/api/health-check" method="post"><button type="submit">VERIFICAR AGORA</button></form>` : ""}
      </div>
    </header>
    ${activeContent}
  </main>
</div>
</body>
</html>`;
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(securityHeaders);
app.use(express.json({ limit: MAX_JSON_BYTES }));
app.use(blockSuspiciousRequest);

app.get("/healthz", (req, res) => {
  res.json({ ok: true });
});

app.get("/", rateLimit("admin", ADMIN_RATE_LIMIT), requireAdmin, (req, res) => {
  res.type("html").send(html(loadState(), req.query.view));
});

app.get("/manifest", rateLimit("device", DEVICE_RATE_LIMIT), requireDevice, (req, res) => {
  const state = loadState();
  const host = publicBaseUrl(req);
  const manifest = state.manifest
    ? { ...state.manifest, download_url: `${host}${withDeviceToken(`/download/${state.manifest.version}`)}` }
    : { version: 0 };
  if (state.command && !state.command.completed_at) {
    manifest.command = state.command;
  }
  res.json(manifest);
});

app.get("/download/:version", rateLimit("device", DEVICE_RATE_LIMIT), requireDevice, (req, res) => {
  const state = loadState();
  const manifest = state.manifest;
  if (!manifest || String(manifest.version) !== String(req.params.version)) {
    res.status(404).send("version not found");
    return;
  }
  const filePath = path.join(UPLOADS_DIR, manifest.stored_name);
  res.download(filePath, manifest.filename);
});

app.post("/heartbeat", rateLimit("device", DEVICE_RATE_LIMIT), requireDevice, (req, res) => {
  const state = loadState();
  const body = req.body || {};
  const deviceId = body.device_id || "unknown";
  state.devices[deviceId] = {
    ...(state.devices[deviceId] || {}),
    ...body,
    last_contact: new Date().toISOString()
  };
  saveState(state);
  const response = { ok: true };
  if (state.command && !state.command.completed_at) {
    response.command = state.command;
  }
  res.json(response);
});

app.post("/status", rateLimit("device", DEVICE_RATE_LIMIT), requireDevice, (req, res) => {
  const state = loadState();
  const body = req.body || {};
  const deviceId = body.device_id || "unknown";
  state.devices[deviceId] = {
    ...(state.devices[deviceId] || {}),
    ...body,
    last_contact: new Date().toISOString()
  };
  addEvent(state, body);
  if (body.event === "HEALTH_CHECK_RESULT" && body.command_id) {
    state.devices[deviceId].last_health_check = {
      time: new Date().toISOString(),
      command_id: body.command_id,
      playback: !!body.playback,
      position_ms: body.position_ms || 0,
      version: body.version,
      update_state: body.update_state,
      last_error: body.last_error || null
    };
    if (state.command && state.command.id === body.command_id) {
      state.command.completed_at = new Date().toISOString();
    }
  }
  saveState(state);
  res.json({ ok: true });
});

app.post("/api/health-check", rateLimit("admin", ADMIN_RATE_LIMIT), requireAdmin, (req, res) => {
  const state = loadState();
  state.command = {
    id: `health-${Date.now()}`,
    type: "HEALTH_CHECK",
    created_at: new Date().toISOString()
  };
  addEvent(state, { event: "HEALTH_CHECK_REQUESTED", update_state: "COMMAND_PENDING" });
  saveState(state);
  res.redirect("/");
});

app.post("/api/publish", rateLimit("admin", ADMIN_RATE_LIMIT), requireAdmin, (req, res) => {
  const busboy = Busboy({
    headers: req.headers,
    limits: {
      files: 1,
      fields: 2,
      fileSize: MAX_UPLOAD_BYTES
    }
  });
  let version = null;
  let uploadPath = null;
  let originalName = "video.mp4";
  let uploadDone = Promise.resolve();
  let uploadRejected = null;

  busboy.on("field", (name, value) => {
    if (name === "version") {
      version = Number(value);
    }
  });

  busboy.on("file", (name, file, info) => {
    if (name !== "video") {
      uploadRejected = "campo de arquivo invalido";
      file.resume();
      return;
    }
    if (info.mimeType && info.mimeType !== "video/mp4" && info.mimeType !== "application/octet-stream") {
      uploadRejected = "tipo de arquivo invalido";
      file.resume();
      return;
    }
    originalName = info.filename || "video.mp4";
    if (!originalName.toLowerCase().endsWith(".mp4")) {
      uploadRejected = "arquivo precisa ser .mp4";
      file.resume();
      return;
    }
    uploadPath = path.join(UPLOADS_DIR, `upload-${Date.now()}.tmp`);
    const out = fs.createWriteStream(uploadPath);
    file.pipe(out);
    uploadDone = new Promise((resolve, reject) => {
      out.on("finish", resolve);
      out.on("error", reject);
      file.on("error", reject);
      file.on("limit", () => {
        uploadRejected = `arquivo maior que o limite (${MAX_UPLOAD_BYTES} bytes)`;
        reject(new Error(uploadRejected));
      });
    });
  });

  busboy.on("filesLimit", () => {
    uploadRejected = "apenas um arquivo por publicacao";
  });

  busboy.on("fieldsLimit", () => {
    uploadRejected = "campos demais na requisicao";
  });

  busboy.on("finish", async () => {
    try {
      await uploadDone;
      if (uploadRejected) {
        throw new Error(uploadRejected);
      }
      if (!Number.isInteger(version) || version <= 0) {
        throw new Error("versao invalida");
      }
      if (!uploadPath || !fs.existsSync(uploadPath)) {
        throw new Error("arquivo nao recebido");
      }
      const size = fs.statSync(uploadPath).size;
      if (size <= 0) {
        throw new Error("arquivo vazio");
      }
      const sha256 = await sha256File(uploadPath);
      const storedName = `video-v${version}.mp4`;
      const storedPath = path.join(UPLOADS_DIR, storedName);
      fs.renameSync(uploadPath, storedPath);

      const state = loadState();
      state.manifest = {
        version,
        filename: "video.mp4",
        original_filename: originalName,
        size,
        sha256,
        stored_name: storedName,
        download_url: `/download/${version}`,
        published_at: new Date().toISOString()
      };
      addEvent(state, { event: "PUBLISHED", update_state: "UPDATE_AVAILABLE", version });
      saveState(state);
      res.redirect("/");
    } catch (err) {
      if (uploadPath && fs.existsSync(uploadPath)) {
        fs.rmSync(uploadPath, { force: true });
      }
      res.status(400).send(String(err.message || err));
    }
  });

  req.pipe(busboy);
});

app.use((err, req, res, next) => {
  if (err && (err.type === "entity.too.large" || err.status === 413)) {
    res.status(413).send("payload too large");
    return;
  }
  if (err instanceof SyntaxError) {
    res.status(400).send("invalid json");
    return;
  }
  next(err);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`AdCast Player server running on http://localhost:${PORT}`);
  for (const ip of localIps()) {
    console.log(`LAN: http://${ip}:${PORT}`);
  }
});
