import { Call, Events, Window, Clipboard } from "/wails/runtime.js";

// Методы Go-сервиса main.Service (cmd/vpnclient/service.go).
const svc = (method, ...args) => Call.ByName("main.Service." + method, ...args);

const $ = (id) => document.getElementById(id);
const app = $("app");

let state = null;
let settings = null;
let ovpn = null;
let version = "";

// ---------- форматирование ----------

function speed(bytes) {
  const units = ["Б/с", "КБ/с", "МБ/с", "ГБ/с"];
  let v = bytes, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  const digits = i === 0 || v >= 100 ? 0 : 1;
  return v.toFixed(digits).replace(".", ",") + " " + units[i];
}

function size(bytes) {
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let v = bytes, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(i < 3 ? 0 : 1).replace(".", ",") + " " + units[i];
}

function validDate(s) {
  if (!s) return null;
  const d = new Date(s);
  return d.getFullYear() > 2000 ? d : null;
}

function elapsed(since) {
  const total = Math.max(0, Math.floor((Date.now() - since.getTime()) / 1000));
  const h = String(Math.floor(total / 3600)).padStart(2, "0");
  const m = String(Math.floor((total % 3600) / 60)).padStart(2, "0");
  const s = String(total % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function setBadge(el, kind, text) {
  el.className = "badge" + (kind ? " " + kind : "");
  el.lastElementChild.textContent = text;
  el.hidden = kind === null;
}

// ---------- главная ----------

function renderMain() {
  if (!state) return;
  const st = state.status;
  app.classList.toggle("connected", st === "connected");
  app.classList.toggle("connecting", st === "connecting");
  app.classList.toggle("error", st === "error");

  const configured = state.proxy.enabled || state.corp.enabled;
  const power = $("power");
  power.setAttribute("aria-label", state.service === "missing" ? "Установить службу"
    : st === "disconnected" || st === "error" ? "Подключить" : "Отключить");

  const titles = { disconnected: "Отключено", connecting: "Подключение…", connected: "Подключено", error: "Ошибка" };
  let title = titles[st];
  let sub = "";
  if (st === "disconnected") sub = configured ? "Нажмите, чтобы подключиться" : "Добавьте подписку или .ovpn в настройках";
  if (st === "connecting") sub = "Запускаем туннель";
  if (st === "error") sub = state.error || "Не удалось подключиться";
  if (st === "connected") sub = elapsed(validDate(state.connectedAt) || new Date());
  // Служба (она держит VPN) ещё не установлена или не отвечает.
  if (state.service === "missing") {
    title = "Нужна установка";
    sub = state.error || "Нажмите, чтобы установить службу VPN. Это нужно один раз.";
  } else if (state.service === "installing") {
    title = "Установка…";
    sub = "Подтвердите запрос Windows на права администратора";
  } else if (state.service === "unavailable") {
    title = "Подождите…";
    sub = "Подключаемся к службе VPN";
  }
  app.classList.toggle("connecting", st === "connecting" || state.service === "installing" || state.service === "unavailable");
  $("status-title").textContent = title;
  $("status-sub").textContent = sub;
  $("status-sub").classList.toggle("copyable", st === "error");
  $("status-sub").title = st === "error" ? "Нажмите, чтобы скопировать" : "";

  $("speed").hidden = st !== "connected";
  $("down").textContent = speed(state.down);
  $("up").textContent = speed(state.up);

  const warnings = state.warnings || [];
  $("notice").hidden = warnings.length === 0;
  $("notice-text").textContent = warnings.slice(0, 2).join("\n") +
    (warnings.length > 2 ? `\nи ещё ${warnings.length - 2}` : "");
  $("notice").dataset.copy = warnings.join("\n");

  // Корпоративная сеть
  const corp = state.corp;
  const active = st === "connecting" || st === "connected";
  if (!corp.enabled) {
    $("corp-sub").textContent = "Не настроено · загрузите .ovpn";
    setBadge($("corp-badge"), null, "");
  } else if (!active) {
    $("corp-sub").textContent = "OpenVPN · " + (corp.domains || "подсети от сервера");
    setBadge($("corp-badge"), "", "выкл");
  } else if (corp.up) {
    $("corp-sub").textContent = "OpenVPN · " + (corp.domains || "работает");
    setBadge($("corp-badge"), "on", "вкл");
  } else {
    $("corp-sub").textContent = "OpenVPN · " + (corp.detail || "подключение…");
    const failed = corp.detail && corp.detail !== "подключение…";
    setBadge($("corp-badge"), failed ? "bad" : "wait", failed ? "ошибка" : "ждём");
  }

  // Зарубежные сайты
  const px = state.proxy;
  if (!px.enabled) {
    $("proxy-sub").textContent = "Не настроено · добавьте подписку";
    setBadge($("proxy-badge"), null, "");
  } else {
    const chosen = px.selected === "auto" || !px.selected ? "авто" : px.selected;
    let text = "VLESS · " + (st === "connected" && px.current ? px.current : chosen);
    if (st === "connected" && px.delay > 0) text += ` · ${px.delay} мс`;
    if (st === "connected" && px.selected === "auto" && px.servers && px.servers.length > 1) text += " · авто";
    $("proxy-sub").textContent = text;
    if (st === "connected") setBadge($("proxy-badge"), "on", "вкл");
    else if (st === "connecting") setBadge($("proxy-badge"), "wait", "ждём");
    else setBadge($("proxy-badge"), "", "выкл");
  }

  $("direct-sub").textContent = settings && !settings.russiaDirect
    ? "Напрямую · только локальная сеть"
    : "Напрямую · российские сайты и LAN";

  if (!$("sheet").hidden) renderServers();
  renderLinkInfo();
}

setInterval(() => {
  if (state && state.status === "connected") {
    $("status-sub").textContent = elapsed(validDate(state.connectedAt) || new Date());
  }
}, 1000);

$("power").addEventListener("click", () => svc("Toggle").catch(showError));

$("route-corp").addEventListener("click", () => showPage("settings"));
$("route-proxy").addEventListener("click", () => {
  if (state && state.proxy.servers && state.proxy.servers.length > 1) openSheet();
  else showPage("settings");
});

// ---------- выбор сервера ----------

function renderServers() {
  const list = $("server-list");
  list.replaceChildren();
  const px = state.proxy;
  const items = [{ name: "auto", label: "Авто — самый быстрый", delay: px.selected === "auto" ? px.delay : 0 }]
    .concat((px.servers || []).map((s) => ({ name: s.name, label: s.name, delay: s.delay })));
  for (const item of items) {
    const btn = document.createElement("button");
    btn.className = "server" + (px.selected === item.name ? " selected" : "");
    const name = document.createElement("span");
    name.className = "server-name";
    name.textContent = item.label;
    const ping = document.createElement("span");
    ping.className = "server-ping" + (item.delay > 0 ? (item.delay < 150 ? " good" : item.delay > 400 ? " slow" : "") : "");
    ping.textContent = item.delay > 0 ? `${item.delay} мс` : "—";
    btn.append(name, ping);
    btn.addEventListener("click", () => {
      // Сервер переключается сразу, подтверждать не нужно.
      $("sheet").hidden = true;
      svc("SelectServer", item.name).catch(showError);
    });
    list.append(btn);
  }
}

function openSheet() {
  renderServers();
  $("sheet").hidden = false;
}

$("btn-sheet-close").addEventListener("click", () => { $("sheet").hidden = true; });
$("sheet").addEventListener("click", (e) => { if (e.target === $("sheet")) $("sheet").hidden = true; });
$("btn-ping").addEventListener("click", async () => {
  const btn = $("btn-ping");
  btn.disabled = true;
  btn.textContent = "Проверяем…";
  try { await svc("TestServers"); } catch (e) { showError(e); }
  btn.disabled = false;
  btn.textContent = "Проверить пинг";
});

// ---------- настройки ----------

function renderSettings() {
  if (!settings) return;
  if (document.activeElement !== $("link")) $("link").value = settings.link || "";
  $("opt-russia").checked = settings.russiaDirect;
  $("opt-autostart").checked = settings.autostart;
  $("opt-connect").checked = settings.connectOnStart;
  $("opt-tray").checked = settings.closeToTray;
  $("version").textContent = version;

  const loaded = ovpn && ovpn.loaded;
  $("ovpn-name").textContent = loaded ? ovpn.name : "Файл не выбран";
  $("ovpn-server").textContent = loaded ? (ovpn.error || ovpn.server) : "Загрузите .ovpn от администратора";
  $("btn-ovpn").textContent = loaded ? "Заменить" : "Выбрать";
  $("btn-ovpn-remove").hidden = !loaded;
  $("ovpn-cert").hidden = !loaded || ovpn.needsAuth || !!ovpn.error;
  $("ovpn-auth").hidden = !loaded || !ovpn.needsAuth;
  $("domains-block").hidden = !loaded;
  if (document.activeElement !== $("ovpn-user")) $("ovpn-user").value = settings.ovpnUsername || "";
  if (document.activeElement !== $("ovpn-pass")) $("ovpn-pass").value = settings.ovpnPassword || "";

  const chips = $("chips");
  chips.querySelectorAll(".chip").forEach((c) => c.remove());
  for (const domain of settings.corpDomains || []) {
    const chip = document.createElement("div");
    chip.className = "chip";
    chip.append(domain);
    const del = document.createElement("button");
    del.setAttribute("aria-label", "Удалить " + domain);
    del.innerHTML = '<svg width="10" height="10" viewBox="0 0 12 12" aria-hidden="true"><path d="M2.5 2.5l7 7M9.5 2.5l-7 7"/></svg>';
    del.addEventListener("click", () => save({ corpDomains: settings.corpDomains.filter((d) => d !== domain) }));
    chip.append(del);
    chips.insertBefore(chip, $("domain-form"));
  }
  renderLinkInfo();
}

function renderLinkInfo() {
  const info = $("link-info");
  if (!state || !settings || !settings.link) { info.hidden = true; return; }
  const px = state.proxy;
  const parts = [];
  if (px.title) parts.push(px.title);
  if (px.servers && px.servers.length) parts.push(`серверов: ${px.servers.length}`);
  if (px.total > 0) parts.push(`${size(px.used)} из ${size(px.total)}`);
  const expire = validDate(px.expire);
  if (expire) parts.push("до " + expire.toLocaleDateString("ru-RU"));
  if (px.outdated) parts.push("не обновилась, используется сохранённая");
  info.hidden = parts.length === 0;
  info.textContent = parts.join(" · ");
  info.classList.toggle("bad", !!px.outdated);
}

async function save(patch) {
  const next = { ...settings, ...patch };
  try {
    await svc("SaveSettings", next);
    settings = next;
  } catch (e) {
    showError(e);
  }
  await reloadSettings();
}

async function reloadSettings() {
  const view = await svc("Settings");
  settings = view.settings;
  ovpn = view.ovpn;
  version = view.version;
  renderSettings();
  renderMain();
}

$("link").addEventListener("change", () => save({ link: $("link").value }));
$("link").addEventListener("keydown", (e) => { if (e.key === "Enter") $("link").blur(); });
$("btn-paste").addEventListener("click", async () => {
  try {
    const text = (await Clipboard.Text()).trim();
    if (!text) return showError("Буфер обмена пуст");
    $("link").value = text;
    await save({ link: text });
  } catch (e) { showError(e); }
});

$("btn-ovpn").addEventListener("click", async () => {
  try {
    const info = await svc("ChooseOVPN");
    if (info) ovpn = info;
  } catch (e) { showError(e); }
  await reloadSettings();
});
$("btn-ovpn-remove").addEventListener("click", async () => {
  try { await svc("RemoveOVPN"); } catch (e) { showError(e); }
  await reloadSettings();
});
$("ovpn-user").addEventListener("change", () => save({ ovpnUsername: $("ovpn-user").value }));
$("ovpn-pass").addEventListener("change", () => save({ ovpnPassword: $("ovpn-pass").value }));

$("domain-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const value = $("domain-input").value.trim();
  if (!value) return;
  $("domain-input").value = "";
  save({ corpDomains: [...(settings.corpDomains || []), value] });
});

$("opt-russia").addEventListener("change", (e) => save({ russiaDirect: e.target.checked }));
$("opt-autostart").addEventListener("change", (e) => save({ autostart: e.target.checked }));
$("opt-connect").addEventListener("change", (e) => save({ connectOnStart: e.target.checked }));
$("opt-tray").addEventListener("change", (e) => save({ closeToTray: e.target.checked }));
$("btn-update").addEventListener("click", async () => {
  try {
    await svc("CheckUpdate");
    showToast("Проверяем обновления…", "info");
    setTimeout(() => reloadSettings().catch(() => {}), 5000);
  } catch (e) { showError(e); }
});

// ---------- навигация и окно ----------

function showPage(name) {
  $("page-main").hidden = name !== "main";
  $("page-settings").hidden = name !== "settings";
  document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.page === name));
}
document.querySelectorAll(".nav-btn").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));

$("btn-minimise").addEventListener("click", () => Window.Minimise());
$("btn-close").addEventListener("click", () => svc("CloseWindow"));

let toastTimer = 0;
function showToast(text, kind) {
  const toast = $("toast");
  toast.textContent = text;
  toast.className = "toast " + kind;
  toast.title = kind === "error" ? "Нажмите, чтобы скопировать" : "";
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, kind === "error" ? 8000 : 1500);
}

function showError(e) {
  showToast(typeof e === "string" ? e : (e && e.message) || String(e), "error");
}

// Тексты ошибок и предупреждений копируются по нажатию — удобно для отладки.
async function copy(text) {
  if (!text) return;
  try {
    await Clipboard.SetText(text);
    showToast("Скопировано", "info");
  } catch (e) {
    showError(e);
  }
}

$("toast").addEventListener("click", () => {
  if ($("toast").classList.contains("error")) copy($("toast").textContent);
  else $("toast").hidden = true;
});
$("notice").addEventListener("click", () => copy($("notice").dataset.copy));
$("status-sub").addEventListener("click", () => {
  if (state && state.status === "error") copy(state.error);
});
$("link-info").addEventListener("click", () => {
  if ($("link-info").classList.contains("bad")) copy($("link-info").textContent);
});

document.addEventListener("contextmenu", (e) => {
  if (!(e.target instanceof HTMLInputElement)) e.preventDefault();
});

// ---------- старт ----------

Events.On("state", (ev) => { state = ev.data; renderMain(); });
Events.On("show-page", (ev) => showPage(ev.data));
Events.On("settings-changed", () => reloadSettings().catch(showError));

(async () => {
  try {
    state = await svc("State");
    await reloadSettings();
  } catch (e) {
    showError(e);
  }
})();
