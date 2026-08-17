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
const STORAGE_MODE_LABEL = STORAGE_DIR === REQUESTED_STORAGE_DIR
  ? "persistente/local"
  : "temporario";

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
  return value ? new Date(value).toLocaleString("pt-BR", {
    dateStyle: "short",
    timeStyle: "medium",
    timeZone: "America/Sao_Paulo"
  }) : "nenhum";
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

function friendlyUpdateState(state) {
  const labels = {
    IDLE: "Tudo certo",
    CHECKING: "Verificando servidor",
    UPDATE_AVAILABLE: "Video novo encontrado",
    DOWNLOADING: "Baixando video",
    DOWNLOADED: "Download terminado",
    VALIDATING: "Conferindo arquivo",
    VALIDATED: "Arquivo aprovado",
    READY_TO_INSTALL: "Pronto para trocar",
    INSTALLING: "Trocando video",
    PLAYER_RESTARTING: "Recarregando player",
    WAITING_PLAYBACK: "Esperando tocar",
    SUCCESS: "Rodando video novo",
    ROLLBACK: "Voltando video anterior",
    UPDATE_FAILED_ROLLED_BACK: "Falhou e voltou",
    FAILED: "Falhou",
    COMMAND_PENDING: "Comando pendente"
  };
  return labels[state] || state || "desconhecido";
}

function stateClass(state) {
  if (["SUCCESS", "IDLE"].includes(state)) {
    return "good";
  }
  if (["FAILED", "ROLLBACK", "UPDATE_FAILED_ROLLED_BACK"].includes(state)) {
    return "danger";
  }
  if (["CHECKING", "UPDATE_AVAILABLE", "DOWNLOADING", "DOWNLOADED", "VALIDATING", "VALIDATED", "READY_TO_INSTALL", "INSTALLING", "WAITING_PLAYBACK", "PLAYER_RESTARTING"].includes(state)) {
    return "warn";
  }
  return "neutral";
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
    ? `${formatDate(lastHealth.time)} | playback=${lastHealth.playback ? "sim" : "nao"} | posicao=${lastHealth.position_ms || 0} ms | estado=${escapeHtml(friendlyUpdateState(lastHealth.update_state))}`
    : "nenhuma";
  const currentUpdateLabel = friendlyUpdateState(latestDevice.update_state);
  const deviceRows = devices.length
    ? devices.map(device => {
      const online = isDeviceOnline(device);
      return `<tr>
        <td><strong>${escapeHtml(device.device_id || "unknown")}</strong></td>
        <td><span class="pill ${online ? "good" : "danger"}">${online ? "ONLINE" : "OFFLINE"}</span></td>
        <td>${escapeHtml(device.version ?? "0")}</td>
        <td>${device.playback ? "RODANDO" : "nao confirmado"}</td>
        <td>${escapeHtml(device.position_ms ?? 0)} ms</td>
        <td><span class="state-badge ${stateClass(device.update_state)}">${escapeHtml(friendlyUpdateState(device.update_state))}</span><small>${escapeHtml(device.update_state || "")}</small></td>
        <td>${formatDate(device.last_contact)}</td>
        <td>${escapeHtml(device.last_error || "nenhum")}</td>
      </tr>`;
    }).join("")
    : `<tr><td colspan="8" class="empty">Nenhuma TV conectou ainda.</td></tr>`;
  const eventRow = e => `<tr>
      <td>${formatDate(e.time)}</td>
      <td>${escapeHtml(e.device_id || "")}</td>
      <td><span class="state-badge ${stateClass(e.update_state)}">${escapeHtml(friendlyUpdateState(e.update_state))}</span><small>${escapeHtml(e.update_state || "")}</small></td>
      <td>${escapeHtml(e.event || "")}</td>
      <td>${escapeHtml(e.version ?? "")}</td>
      <td>${escapeHtml(e.last_error || "")}</td>
    </tr>`;
  const eventRows = (state.events || []).length
    ? state.events.map(eventRow).join("")
    : `<tr><td colspan="6" class="empty">Nenhum evento registrado ainda.</td></tr>`;
  const dashboardEventRows = (state.events || []).length
    ? state.events.slice(0, 8).map(eventRow).join("")
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
            <dt>Estado update</dt><dd><span class="state-badge ${stateClass(latestDevice.update_state)}">${escapeHtml(friendlyUpdateState(latestDevice.update_state))}</span></dd>
            <dt>Ultimo erro</dt><dd>${escapeHtml(latestDevice.last_error || "nenhum")}</dd>
          </dl>
        </div>
        <div>
          <h3>Verificacao remota</h3>
          <dl>
            <dt>Pedido atual</dt><dd>${pendingCommand ? `aguardando resposta (${escapeHtml(pendingCommand.id)})` : "nenhum"}</dd>
            <dt>Ultima verificacao</dt><dd>${latestHealthText}</dd>
            <dt>Erros ativos</dt><dd>${errorCount}</dd>
            <dt>Video publicado</dt><dd>${manifest ? `versao ${escapeHtml(manifest.version)} - ${formatBytes(manifest.size)}` : "nenhum"}</dd>
          </dl>
        </div>
      </div>
    </section>
    <section class="status-strip">
      <div>
        <span>Status operacional</span>
        <strong>${escapeHtml(currentUpdateLabel)}</strong>
      </div>
      <div>
        <span>Proxima acao esperada</span>
        <strong>${pendingCommand ? "Aguardar resposta da TV" : updatingCount ? "Aguardar a TV concluir" : "Nenhuma acao pendente"}</strong>
      </div>
      <div>
        <span>Atualizacao automatica</span>
        <strong>A cada 15 segundos</strong>
      </div>
    </section>
    <section>
      <div class="section-title-row">
        <h3>Eventos recentes</h3>
        <a class="text-link" href="/?view=events">Ver historico completo</a>
      </div>
      <div class="table-wrap">
        <table>
          <tr><th>Hora</th><th>Dispositivo</th><th>Estado</th><th>Evento</th><th>Versao</th><th>Erro</th></tr>
          ${dashboardEventRows}
        </table>
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
      <form id="publish-form" action="/api/publish" method="post" enctype="multipart/form-data">
        <label>Arquivo MP4</label>
        <input id="video-file" name="video" type="file" accept="video/mp4" required>
        <label>Versao</label>
        <input id="video-version" name="version" type="number" min="1" step="1" value="${nextVersion}" required>
        <div class="upload-panel" id="upload-panel">
          <div class="upload-meta">
            <strong id="upload-title">Aguardando arquivo</strong>
            <span id="upload-detail">Selecione um MP4 para publicar.</span>
          </div>
          <div class="progress"><div id="upload-bar"></div></div>
          <ol class="upload-log" id="upload-log">
            <li>Pronto para enviar um novo video.</li>
          </ol>
          <div class="upload-actions">
            <button id="publish-button" type="submit">PUBLICAR ATUALIZACAO</button>
            <button id="cancel-upload" class="secondary" type="button" disabled>CANCELAR ENVIO</button>
            <a class="button-link" href="/?view=dashboard">ACOMPANHAR DASHBOARD</a>
          </div>
        </div>
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
        <dt>Tipo storage</dt><dd><span class="state-badge ${STORAGE_MODE_LABEL === "temporario" ? "warn" : "good"}">${STORAGE_MODE_LABEL}</span></dd>
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
      --bg: #101418;
      --panel: #191f26;
      --panel-soft: #202833;
      --ink: #edf3f7;
      --muted: #93a3b3;
      --line: #303a46;
      --nav: #151a21;
      --accent: #2d8cff;
      --accent-strong: #57c4ff;
      --good: #35d07f;
      --warn: #ffbd4a;
      --danger: #ff6b5f;
      --neutral: #9ca8b5;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Inter, Arial, sans-serif; background: var(--bg); color: var(--ink); }
    .shell { display: grid; grid-template-columns: 248px minmax(0, 1fr); min-height: 100vh; }
    aside { position: sticky; top: 0; height: 100vh; padding: 22px 18px; background: var(--nav); color: white; border-right: 1px solid var(--line); }
    aside h1 { font-size: 20px; margin: 0 0 4px; letter-spacing: 0; }
    aside p { color: var(--muted); font-size: 13px; margin: 0 0 24px; }
    nav a { display: block; color: #c8d2dd; text-decoration: none; padding: 11px 12px; border-radius: 8px; margin-bottom: 6px; font-weight: 700; border: 1px solid transparent; }
    nav a:hover, nav a.active { background: #24303d; color: white; border-color: #3a4654; }
    nav a.active { box-shadow: inset 3px 0 0 var(--accent-strong); }
    main { padding: 30px; max-width: 1380px; width: 100%; }
    header { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; margin-bottom: 18px; }
    header h2 { font-size: 28px; margin: 0 0 4px; letter-spacing: 0; }
    header p { margin: 0; color: var(--muted); }
    section { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 18px; margin-bottom: 16px; box-shadow: 0 14px 30px rgba(0, 0, 0, 0.18); }
    section h3 { font-size: 18px; margin: 0 0 14px; }
    label { display: block; font-weight: 700; margin: 12px 0 6px; }
    input, button { font: inherit; }
    input[type="number"], input[type="file"] { width: 100%; padding: 11px; border: 1px solid #3b4654; border-radius: 8px; background: #11161c; color: var(--ink); }
    input[type="file"]::file-selector-button { margin-right: 10px; border: 0; border-radius: 6px; padding: 8px 10px; background: #2a3440; color: var(--ink); font-weight: 700; cursor: pointer; }
    button, .button-link { margin-top: 14px; padding: 10px 14px; border: 0; border-radius: 8px; background: var(--accent); color: white; font-weight: 800; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; min-height: 42px; }
    button:hover, .button-link:hover { filter: brightness(1.08); }
    button:disabled { cursor: not-allowed; opacity: 0.65; }
    button.secondary { background: #2a3440; color: #dbe6ee; }
    dl { display: grid; grid-template-columns: 150px 1fr; gap: 8px 14px; margin: 0; }
    dt { font-weight: 700; color: #c3ced8; }
    dd { margin: 0; word-break: break-word; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 11px 8px; border-bottom: 1px solid var(--line); text-align: left; font-size: 14px; vertical-align: top; }
    tr:hover td { background: rgba(255, 255, 255, 0.025); }
    th { color: #aab8c6; font-size: 12px; text-transform: uppercase; letter-spacing: 0; }
    td small { display: block; margin-top: 2px; color: var(--muted); font-size: 11px; }
    code { background: #11161c; border: 1px solid #2d3642; color: #b9ddff; padding: 2px 5px; border-radius: 4px; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px; }
    .metric { background: var(--panel-soft); border: 1px solid var(--line); border-radius: 8px; padding: 14px; }
    .metric span { display: block; color: var(--muted); font-size: 13px; font-weight: 700; }
    .metric strong { display: block; font-size: 28px; margin-top: 6px; }
    .split { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(300px, 0.9fr); gap: 16px; }
    .pill { display: inline-block; min-width: 76px; text-align: center; padding: 4px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; }
    .good { color: var(--good); background: rgba(53, 208, 127, 0.12); }
    .warn { color: var(--warn); background: rgba(255, 189, 74, 0.13); }
    .danger { color: var(--danger); background: rgba(255, 107, 95, 0.13); }
    .neutral { color: var(--neutral); background: rgba(156, 168, 181, 0.12); }
    .state-badge { display: inline-block; padding: 4px 8px; border-radius: 999px; font-size: 12px; font-weight: 800; }
    .empty { color: var(--muted); text-align: center; padding: 24px 8px; }
    .table-wrap { overflow-x: auto; }
    .server-list { display: flex; flex-wrap: wrap; gap: 6px; }
    .inline { display: inline; }
    .header-actions { min-width: 170px; text-align: right; }
    .section-title-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
    .section-title-row h3 { margin: 0; }
    .text-link { color: var(--accent-strong); text-decoration: none; font-weight: 800; }
    .text-link:hover { text-decoration: underline; }
    .status-strip { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; background: #121820; }
    .status-strip div { background: var(--panel-soft); border: 1px solid var(--line); border-radius: 8px; padding: 14px; }
    .status-strip span { display: block; color: var(--muted); font-size: 13px; font-weight: 700; margin-bottom: 6px; }
    .status-strip strong { font-size: 16px; }
    .upload-panel { margin-top: 14px; border: 1px solid var(--line); border-radius: 8px; padding: 14px; background: var(--panel-soft); }
    .upload-meta { display: flex; flex-direction: column; gap: 4px; color: var(--muted); }
    .upload-meta strong { color: var(--ink); }
    .progress { height: 12px; margin-top: 12px; overflow: hidden; border-radius: 999px; background: #10161d; border: 1px solid #2d3743; }
    .progress div { width: 0%; height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent-strong)); transition: width 0.2s ease; }
    .upload-log { margin: 14px 0 0; padding: 12px 12px 12px 28px; min-height: 92px; max-height: 180px; overflow: auto; background: #11161c; border: 1px solid #2d3642; border-radius: 8px; color: #cfd9e3; }
    .upload-log li { margin: 0 0 6px; }
    .upload-actions { display: flex; flex-wrap: wrap; gap: 10px; }
    .state-label { font-weight: 700; }
    @media (max-width: 900px) {
      .shell { grid-template-columns: 1fr; }
      aside { position: static; height: auto; }
      nav { display: flex; flex-wrap: wrap; gap: 6px; }
      nav a { margin: 0; }
      main { padding: 18px; }
      header { display: block; }
      .grid, .split, .status-strip { grid-template-columns: 1fr; }
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
<script>
(() => {
  const activeView = ${JSON.stringify(activeView)};
  if (activeView === "dashboard" || activeView === "events" || activeView === "devices") {
    setTimeout(() => window.location.reload(), 15000);
  }

  const form = document.getElementById("publish-form");
  if (!form) return;

  const fileInput = document.getElementById("video-file");
  const versionInput = document.getElementById("video-version");
  const publishButton = document.getElementById("publish-button");
  const cancelButton = document.getElementById("cancel-upload");
  const title = document.getElementById("upload-title");
  const detail = document.getElementById("upload-detail");
  const bar = document.getElementById("upload-bar");
  const log = document.getElementById("upload-log");
  let xhr = null;
  let completedUploadLogged = false;

  const addLog = (message) => {
    const item = document.createElement("li");
    item.textContent = new Date().toLocaleTimeString("pt-BR") + " - " + message;
    log.prepend(item);
  };

  const setLocked = (locked) => {
    publishButton.disabled = locked;
    cancelButton.disabled = !locked;
    fileInput.disabled = locked;
    versionInput.disabled = locked;
  };

  const formatBytesClient = (bytes) => {
    const units = ["B", "KB", "MB", "GB"];
    let size = Number(bytes || 0);
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
      size /= 1024;
      unit += 1;
    }
    return size.toFixed(unit === 0 ? 0 : 1) + " " + units[unit];
  };

  fileInput.addEventListener("change", () => {
    const file = fileInput.files && fileInput.files[0];
    bar.style.width = "0%";
    if (!file) {
      title.textContent = "Aguardando arquivo";
      detail.textContent = "Selecione um MP4 para publicar.";
      return;
    }
    title.textContent = file.name;
    detail.textContent = "Tamanho: " + formatBytesClient(file.size);
    addLog("Arquivo selecionado: " + file.name + " (" + formatBytesClient(file.size) + ").");
  });

  cancelButton.addEventListener("click", () => {
    if (xhr) {
      xhr.abort();
    }
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const file = fileInput.files && fileInput.files[0];
    if (!file) {
      title.textContent = "Selecione um arquivo MP4";
      detail.textContent = "Nenhum arquivo foi escolhido.";
      addLog("Publicacao bloqueada: nenhum arquivo selecionado.");
      return;
    }

    const data = new FormData();
    data.append("video", file);
    data.append("version", versionInput.value);

    xhr = new XMLHttpRequest();
    completedUploadLogged = false;
    setLocked(true);
    title.textContent = "Enviando video...";
    detail.textContent = "0% enviado de " + formatBytesClient(file.size);
    bar.style.width = "0%";
    addLog("Envio iniciado para a versao " + versionInput.value + ".");

    xhr.upload.onprogress = (e) => {
      if (!e.lengthComputable) {
        detail.textContent = "Enviando... tamanho total nao informado pelo navegador.";
        return;
      }
      const percent = Math.min(100, Math.round((e.loaded / e.total) * 100));
      bar.style.width = percent + "%";
      detail.textContent = percent + "% enviado (" + formatBytesClient(e.loaded) + " de " + formatBytesClient(e.total) + ")";
      if (percent === 100 && !completedUploadLogged) {
        completedUploadLogged = true;
        addLog("Upload chegou em 100%. Servidor esta conferindo o arquivo.");
      }
    };

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 400) {
        title.textContent = "Upload concluido";
        detail.textContent = "Video publicado. A TV vai baixar na proxima consulta.";
        bar.style.width = "100%";
        addLog("Servidor confirmou a publicacao. Indo para o dashboard.");
        setTimeout(() => {
          window.location.href = "/?view=dashboard";
        }, 1800);
        return;
      }
      title.textContent = "Falha ao publicar";
      let errorMessage = xhr.responseText || ("HTTP " + xhr.status);
      try {
        errorMessage = JSON.parse(xhr.responseText).error || errorMessage;
      } catch {
        // resposta nao era JSON
      }
      detail.textContent = errorMessage;
      addLog("Falha do servidor: " + detail.textContent);
      setLocked(false);
      xhr = null;
    };

    xhr.onerror = () => {
      title.textContent = "Falha de rede";
      detail.textContent = "O navegador nao conseguiu concluir o envio.";
      addLog("Falha de rede durante o envio.");
      setLocked(false);
      xhr = null;
    };

    xhr.onabort = () => {
      title.textContent = "Envio cancelado";
      detail.textContent = "O upload foi interrompido antes da confirmacao.";
      bar.style.width = "0%";
      addLog("Envio cancelado pelo painel.");
      setLocked(false);
      xhr = null;
    };

    xhr.open("POST", "/api/publish");
    xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
    xhr.send(data);
  });
})();
</script>
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
  const wantsJson = req.get("x-requested-with") === "XMLHttpRequest";
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
      if (wantsJson) {
        res.json({ ok: true, version, size });
      } else {
        res.redirect("/?view=dashboard");
      }
    } catch (err) {
      if (uploadPath && fs.existsSync(uploadPath)) {
        fs.rmSync(uploadPath, { force: true });
      }
      const message = String(err.message || err);
      if (wantsJson) {
        res.status(400).json({ ok: false, error: message });
      } else {
        res.status(400).send(message);
      }
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
