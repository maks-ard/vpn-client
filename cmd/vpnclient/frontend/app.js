import { Call, Events, Window, Clipboard } from "/wails/runtime.js";
import { serverLabels, serverIcon } from "./servers.js";
import { subscriptionExpiry } from "./subscription.js";

// Методы Go-сервиса main.Service (cmd/vpnclient/service.go).
const svc = (method, ...args) => Call.ByName("main.Service." + method, ...args);

const $ = (id) => document.getElementById(id);
const app = $("app");

let state = null;
let settings = null;
let ovpn = null;
let version = "";
let draft = null;
let savedSettings = null;
let previousSettings = null;
let updateRefresh = 0;
let update = { state: "", version: "", progress: 0 };

function friendlyServer(name) {
  if (!name || name === "auto") return "авто";
  return serverLabels(state?.proxy.servers || []).find(s => s.name === name)?.label || "Сервер";
}

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
    : state.service === "unavailable" && state.error ? "Перезапустить службу"
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
    sub = "Подтвердите запрос Windows на права администратора. Не видно запроса — нажмите на мигающий значок на панели задач.";
  } else if (state.service === "unavailable") {
    title = !state.error ? "Подождите…" : state.error.startsWith("Служба остановлена") ? "Служба остановлена" : "Служба не отвечает";
    sub = state.error || "Подключаемся к службе VPN";
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
    // «подключение…» и «переподключение…» — ожидание, а не ошибка.
    const failed = corp.detail && !corp.detail.endsWith("…");
    setBadge($("corp-badge"), failed ? "bad" : "wait", failed ? "ошибка" : "ждём");
  }

  // Зарубежные сайты
  const px = state.proxy;
  if (!px.enabled) {
    $("proxy-sub").textContent = "Не настроено · добавьте подписку";
    setBadge($("proxy-badge"), null, "");
  } else {
    const chosen = friendlyServer(px.selected);
    let text = "VLESS · " + (st === "connected" && px.current ? friendlyServer(px.current) : chosen);
    if (st === "connected" && px.delay > 0) text += ` · ${px.delay} мс`;
    if (st === "connected" && px.selected === "auto" && px.servers && px.servers.length > 1) text += " · авто";
    $("proxy-sub").textContent = text;
    if (st === "connected") {
      const checks = px.checks || [];
      setBadge($("proxy-badge"), checks.length ? (checks.some(c => c.ok) ? "on" : "bad") : "wait", checks.length ? (checks.some(c => c.ok) ? "доступен" : "нет связи") : "проверка");
    }
    else if (st === "connecting") setBadge($("proxy-badge"), "wait", "ждём");
    else setBadge($("proxy-badge"), "", "выкл");
  }

  $("direct-sub").textContent = settings && !settings.russiaDirect
    ? "Напрямую · только локальная сеть"
    : "Напрямую · российские сайты и LAN";

  if (!$("sheet").hidden) renderServers();
  renderLinkInfo();
  renderChecks();
}

function renderChecks() {
  const list = $("service-checks");
  list.replaceChildren();
  const checks = state?.proxy.checks || [];
  $("checks-block").hidden = !state?.proxy.enabled;
  $("btn-check-now").disabled = state?.status !== "connected";
  for (const check of checks) {
    const row = document.createElement("div");
    row.className = "check-row";
    const name = document.createElement("span"); name.textContent = check.name;
    const result = document.createElement("span");
    result.className = check.ok ? "check-ok" : "check-bad";
    result.textContent = check.ok ? `${check.delay} мс` : "Нет ответа";
    row.append(name, result); list.append(row);
  }
  $("checks-time").textContent = checks.length
    ? "Проверено " + new Date(checks[0].checkedAt).toLocaleTimeString("ru-RU")
    : "Ещё не проверено";
}

setInterval(() => {
  if (state && state.status === "connected") {
    $("status-sub").textContent = elapsed(validDate(state.connectedAt) || new Date());
  }
}, 1000);

$("power").addEventListener("click", () => {
  if (settings && !(settings.link || "").trim() && !(ovpn && ovpn.loaded) && !(state && state.service)) {
    showPage("settings");
    $("link").focus();
    showToast("Добавьте подписку или файл OpenVPN", "info");
    return;
  }
  svc("Toggle").catch(showError);
});

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
  const items = [{ name: "auto", label: "Автовыбор", delay: px.selected === "auto" ? px.delay : 0, code: "" }]
    .concat(serverLabels(px.servers || []));
  for (const item of items) {
    const btn = document.createElement("button");
    btn.className = "server" + (px.selected === item.name ? " selected" : "");
    const name = document.createElement("span");
    name.className = "server-name";
    name.textContent = item.label;
    btn.title = item.name === "auto" ? "Самый быстрый по HTTP-проверке YouTube" : item.name;
    btn.setAttribute("aria-pressed", String(px.selected === item.name));
    const ping = document.createElement("span");
    ping.className = "server-ping" + (item.delay > 0 ? (item.delay < 150 ? " good" : item.delay > 400 ? " slow" : "") : "");
    ping.textContent = item.delay > 0 ? `${item.delay} мс` : "—";
    btn.append(serverIcon(item.code), name, ping);
    btn.addEventListener("click", async () => {
      // Сервер переключается сразу, подтверждать не нужно.
      btn.disabled = true;
      try { await svc("SelectServer", item.name); $("sheet").hidden = true; }
      catch (err) { showError(err); }
      finally { btn.disabled = false; }
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
  btn.textContent = "Проверить задержку";
});

$("btn-check-now").addEventListener("click", async () => {
  const btn = $("btn-check-now"); btn.disabled = true; btn.textContent = "Проверяем…";
  try { await svc("TestServers"); } catch (err) { showError(err); }
  finally { btn.disabled = false; btn.textContent = "Проверить сейчас"; }
});
$("btn-setup-connect").addEventListener("click", () => {
  if (draft) { $("btn-apply").focus(); showToast("Сначала примените настройки", "info"); return; }
  if (!(settings?.link || "").trim() && !ovpn?.loaded) {
    showToast("Добавьте файл OpenVPN или ссылку VLESS", "info"); return;
  }
  showPage("main");
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
  $("setup-intro").hidden = !!loaded || !!(settings.link || "").trim();
  $("ovpn-path-form").hidden = !!loaded && !replacingOVPN;
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
  const expiry = $("subscription-expiry");
  const mainExpiry = $("subscription-expiry-main");
  expiry.hidden = true;
  mainExpiry.hidden = true;
  if (state && settings && /^https?:\/\//i.test(settings.link || "")) {
    const result = subscriptionExpiry(state.proxy.expire);
    expiry.hidden = false;
    expiry.textContent = result.text + (state.proxy.outdated ? " · сохранённые данные" : "");
    expiry.className = "subscription-expiry" + (result.expired ? " expired" : result.soon ? " soon" : "");
    expiry.title = result.detail || "Срок передаётся провайдером в заголовке Subscription-Userinfo при загрузке подписки.";
    if (state.proxy.metadataError && !validDate(state.proxy.updated)) expiry.textContent = "Не удалось получить срок подписки. Повторим проверку позже";
    else if (!validDate(state.proxy.updated) && !validDate(state.proxy.expire)) expiry.textContent = "Загружаем сведения о подписке…";
    mainExpiry.hidden = false;
    mainExpiry.textContent = expiry.textContent;
    mainExpiry.className = expiry.className;
    mainExpiry.title = expiry.title;
  }
  if (!state || !settings || !settings.link) { info.hidden = true; return; }
  const px = state.proxy;
  const parts = [];
  if (px.title) parts.push(px.title);
  if (px.servers && px.servers.length) parts.push(`серверов: ${px.servers.length}`);
  if (px.total > 0) parts.push(`${size(px.used)} из ${size(px.total)}`);
    if (px.outdated) parts.push("используются сохранённые данные");
  info.hidden = parts.length === 0;
  info.textContent = parts.join(" · ");
  info.classList.toggle("bad", !!px.outdated);
}

async function save(patch) {
  if (!savedSettings) savedSettings = { ...settings };
  draft = { ...(draft || settings), ...patch };
  settings = draft;
  $("settings-actions").hidden = false;
  $("settings-impact").textContent = state?.status === "connected"
    ? "Применение маршрутов и учётных данных переподключит VPN."
    : "Изменения ещё не применены.";
  renderSettings();
}

$("btn-apply").addEventListener("click", async () => {
  if (!draft) return;
  const btn = $("btn-apply"); btn.disabled = true;
  try {
    await svc("SaveSettings", draft);
    previousSettings = savedSettings;
    draft = null; savedSettings = null;
    $("settings-actions").hidden = true;
    $("btn-settings-undo").hidden = false;
    await reloadSettings();
    showToast("Настройки применены", "info");
  } catch (e) {
    showError(e);
  } finally { btn.disabled = false; }
});
$("btn-discard").addEventListener("click", async () => {
  draft = null; savedSettings = null; $("settings-actions").hidden = true;
  await reloadSettings();
});
$("btn-settings-undo").addEventListener("click", async () => {
  if (!previousSettings) return;
  try {
    await svc("SaveSettings", previousSettings);
    previousSettings = null; draft = null; savedSettings = null;
    $("settings-actions").hidden = true; $("btn-settings-undo").hidden = true;
    await reloadSettings();
  } catch (err) { showError(err); }
});

async function reloadSettings() {
  const view = await svc("Settings");
  settings = draft || view.settings;
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

let replacingOVPN = false;
$("btn-ovpn").addEventListener("click", async () => {
  replacingOVPN = true;
  renderSettings();
  await findOVPN();
});
$("btn-ovpn-browse").addEventListener("click", async () => {
  try {
    const info = await svc("ChooseOVPN");
    if (info) { ovpn = info; replacingOVPN = false; }
  } catch (e) { showError(e); }
  await reloadSettings();
});
$("ovpn-path-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const path = $("ovpn-path").value.trim();
  if (!path) { $("ovpn-path").focus(); return; }
  const btn = $("btn-ovpn-load");
  btn.disabled = true;
  btn.textContent = "Загрузка…";
  try {
    ovpn = await svc("LoadOVPN", path);
    replacingOVPN = false;
    $("ovpn-path").value = "";
    await reloadSettings();
    showToast("Конфигурация OpenVPN загружена", "info");
  } catch (err) { showError(err); }
  finally { btn.disabled = false; btn.textContent = "Загрузить"; }
});

let discoveryStarted = false;
async function findOVPN() {
  const btn = $("btn-ovpn-find");
  const list = $("ovpn-found");
  btn.disabled = true;
  btn.textContent = "Ищем…";
  list.replaceChildren();
  list.hidden = false;
  try {
    const profiles = await svc("FindOVPN");
    if (!profiles.length) {
      list.textContent = "Профили не найдены. Выберите файл вручную.";
      list.classList.add("hint");
    } else {
      list.classList.remove("hint");
      for (const profile of profiles) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "btn found-profile";
        button.textContent = profile.name;
        const path = document.createElement("small");
        path.textContent = profile.path;
        button.append(path);
        button.addEventListener("click", async () => {
          button.disabled = true;
          try {
            await svc("LoadOVPN", profile.path);
            replacingOVPN = false;
            await reloadSettings();
            $("ovpn-path").value = "";
            showToast("Конфигурация OpenVPN загружена", "info");
          } catch (err) { showError(err); }
          finally { button.disabled = false; }
        });
        list.append(button);
      }
    }
  } catch (err) { list.hidden = true; showError(err); }
  finally { btn.disabled = false; btn.textContent = "Повторить поиск"; }
}
$("btn-ovpn-find").addEventListener("click", findOVPN);
$("btn-ovpn-remove").addEventListener("click", async () => {
  try { await svc("RemoveOVPN"); } catch (e) { showError(e); }
  await reloadSettings();
});
$("ovpn-user").addEventListener("change", () => save({ ovpnUsername: $("ovpn-user").value }));
$("ovpn-pass").addEventListener("change", () => save({ ovpnPassword: $("ovpn-pass").value }));
$("btn-password").addEventListener("click", () => {
  const visible = $("ovpn-pass").type === "password";
  $("ovpn-pass").type = visible ? "text" : "password";
  $("btn-password").textContent = visible ? "Скрыть" : "Показать";
  $("btn-password").setAttribute("aria-pressed", String(visible));
});

$("btn-diagnostics").addEventListener("click", () => {
  // Только разрешённые поля: журнал, адреса, имена серверов и настройки с
  // паролями не попадают в отчёт даже при нестандартном формате подписки.
  const report = {
    version: version.match(/Версия [\w.+-]+(?: · sing-box [\w.+-]+)?/)?.[0] || "неизвестно",
    time: new Date().toISOString(),
    service: state?.service || "доступна",
    process: state?.status || "неизвестно",
    corporate: { enabled: !!state?.corp.enabled, reachable: !!state?.corp.up },
    proxy: { enabled: !!state?.proxy.enabled, serverCount: state?.proxy.servers?.length || 0, delay: state?.proxy.delay || 0 },
    checks: (state?.proxy.checks || []).filter(c => ["YouTube", "Instagram", "ChatGPT", "Claude"].includes(c.name)).map(c => ({ name: c.name, ok: c.ok, delay: c.delay, checkedAt: c.checkedAt })),
  };
  $("diagnostics-preview").value = JSON.stringify(report, null, 2);
  $("diagnostics-block").hidden = false;
});
$("btn-diagnostics-copy").addEventListener("click", () => copy($("diagnostics-preview").value));

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
    clearInterval(updateRefresh);
    let polls = 0;
    updateRefresh = setInterval(() => {
      reloadSettings().catch(() => {});
      if (++polls >= 30) clearInterval(updateRefresh);
    }, 2000);
  } catch (e) { showError(e); }
});

// ---------- навигация и окно ----------

function showPage(name) {
  $("page-main").hidden = name !== "main";
  $("page-settings").hidden = name !== "settings";
  document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.page === name));
  if (name === "settings" && ovpn && !ovpn.loaded && !discoveryStarted) {
    discoveryStarted = true;
    findOVPN();
  }
  hideHelp();
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

// Собственная геометрическая SVG-иконка, без внешних загрузок и лицензий.
const tooltip = $("help-tooltip");
let helpOwner = null;
function hideHelp() {
  tooltip.hidden = true;
  helpOwner?.removeAttribute("aria-describedby");
  helpOwner = null;
}
for (const button of document.querySelectorAll(".info-btn")) {
  button.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/></svg>';
  const showHelp = () => {
    hideHelp();
    helpOwner = button;
    tooltip.textContent = button.dataset.help;
    tooltip.hidden = false;
    button.setAttribute("aria-describedby", "help-tooltip");
    const rect = button.getBoundingClientRect();
    tooltip.style.left = Math.max(12, Math.min(rect.left, window.innerWidth - tooltip.offsetWidth - 12)) + "px";
    tooltip.style.top = (rect.bottom + tooltip.offsetHeight + 8 < window.innerHeight
      ? rect.bottom + 6 : Math.max(8, rect.top - tooltip.offsetHeight - 6)) + "px";
  };
  button.addEventListener("mouseenter", showHelp);
  button.addEventListener("focus", showHelp);
  button.addEventListener("mouseleave", (e) => { if (!tooltip.contains(e.relatedTarget)) hideHelp(); });
  button.addEventListener("blur", hideHelp);
  button.addEventListener("click", showHelp);
}
tooltip.addEventListener("mouseleave", hideHelp);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") hideHelp(); });
$("page-settings").addEventListener("scroll", hideHelp);

// ---------- обновление ----------

function renderUpdate() {
  const bar = $("update-bar");
  bar.hidden = !update.state;
  if (!update.state) return;
  const name = update.version ? "Обновление " + update.version : "Обновление";
  const btn = $("btn-install-update");
  const progress = $("update-progress");
  const vpnOn = state && (state.status === "connected" || state.status === "connecting");
  if (update.state === "downloading") {
    const known = update.progress >= 0;
    $("update-title").textContent = "Загружается " + name.toLowerCase();
    $("update-sub").textContent = known ? update.progress + "%" : "Загрузка…";
    progress.hidden = false;
    progress.classList.toggle("indeterminate", !known);
    $("update-progress-fill").style.width = known ? update.progress + "%" : "";
    if (known) progress.setAttribute("aria-valuenow", update.progress); else progress.removeAttribute("aria-valuenow");
    btn.hidden = true;
  } else {
    const installing = update.state === "installing";
    $("update-title").textContent = installing ? "Устанавливается " + name.toLowerCase() + "…" : name + " готово";
    $("update-sub").textContent = installing ? "Приложение перезапустится"
      : vpnOn ? "VPN ненадолго отключится и подключится снова" : "Установка займёт несколько секунд";
    progress.hidden = true;
    btn.hidden = false;
    btn.disabled = installing;
  }
}

$("btn-install-update").addEventListener("click", async () => {
  const btn = $("btn-install-update");
  btn.disabled = true;
  try {
    await svc("InstallUpdate");
    update = { ...update, state: "installing" };
    renderUpdate();
  } catch (e) {
    btn.disabled = false;
    showError(e);
  }
});

Events.On("update", (ev) => {
  const changed = ev.data.state !== update.state;
  update = ev.data;
  renderUpdate();
  // Строка версии прячет статус загрузки, пока видна плашка.
  if (changed) reloadSettings().catch(() => {});
});
Events.On("state", (ev) => { state = ev.data; renderMain(); renderUpdate(); });
Events.On("show-page", (ev) => showPage(ev.data));
Events.On("settings-changed", () => reloadSettings().catch(showError));

(async () => {
  try {
    state = await svc("State");
    update = await svc("Update");
    renderUpdate();
    await reloadSettings();
    if (!(settings.link || "").trim() && !(ovpn && ovpn.loaded)) {
      showPage("settings");
    }
  } catch (e) {
    showError(e);
  }
})();
