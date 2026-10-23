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
// null — поиск .ovpn ещё не запускался.
let profiles = null;
let searching = false;

const icons = {
  file: '<svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path d="M14 3H6v18h12V7l-4-4z"/><path d="M14 3v4h4"/></svg>',
  bolt: '<svg width="14" height="14" viewBox="0 0 24 24" aria-hidden="true"><path d="M13 3L5 14h6l-1 7 8-11h-6l1-7z"/></svg>',
  check: '<svg class="check" width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12l5 5 9-10"/></svg>',
  close: '<svg width="10" height="10" viewBox="0 0 12 12" aria-hidden="true"><path d="M2.5 2.5l7 7M9.5 2.5l-7 7"/></svg>',
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function html(tag, className, markup) {
  const node = el(tag, className);
  node.innerHTML = markup;
  return node;
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

function plural(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
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

// Флаг рисуется локально (servers.js): emoji-флаги в Windows не отображаются.
function flag(code, className) {
  const svg = serverIcon(code);
  svg.removeAttribute("width");
  svg.removeAttribute("height");
  if (code) {
    svg.setAttribute("viewBox", "0 2 32 20");
    svg.setAttribute("preserveAspectRatio", "none");
  }
  svg.classList.add(className);
  return svg;
}

function isSubscription() {
  return /^https?:\/\//i.test(settings?.link || "");
}

function configured() {
  return !!(settings?.link || "").trim() || !!ovpn?.loaded;
}

// Без настроек главная предлагает добавить подключение. Если что-то со
// службой, остаётся обычный экран: кнопка питания ставит или перезапускает её.
function onboardingVisible() {
  return !!settings && !configured() && !state?.service;
}

function subscriptionStatus() {
  const px = state.proxy;
  const result = subscriptionExpiry(px.expire);
  let text = result.text;
  const expire = validDate(px.expire);
  if (expire && !result.expired) {
    const days = Math.max(1, Math.ceil((expire.getTime() - Date.now()) / 86400000));
    text += ` · ${days} ${plural(days, "день", "дня", "дней")}`;
  }
  if (px.outdated) text += " · сохранённые данные";
  let message = "";
  if (px.metadataError && !validDate(px.updated)) message = "Не удалось получить срок подписки. Повторим проверку позже";
  else if (!validDate(px.updated) && !expire) message = "Загружаем сведения о подписке…";
  return {
    ...result,
    text: message || text,
    message,
    className: result.expired ? "expired" : result.soon ? "soon" : "",
    title: result.detail || "Срок передаётся провайдером в заголовке Subscription-Userinfo при загрузке подписки.",
  };
}

// ---------- главная ----------

function renderMain() {
  if (!state) return;
  const st = state.status;
  const serviceIssue = !!state.service;
  const failed = st === "error" && !serviceIssue;
  app.classList.toggle("connected", st === "connected");
  app.classList.toggle("error", st === "error");

  const onboarding = onboardingVisible();
  $("onboarding").hidden = !onboarding;
  $("main-view").hidden = onboarding;
  if (onboarding && profiles === null && !searching) findOVPN();

  const power = $("power");
  power.setAttribute("aria-label", state.service === "missing" ? "Установить службу"
    : state.service === "unavailable" && state.error ? "Перезапустить службу"
    : st === "disconnected" || st === "error" ? "Подключить" : "Отключить");

  const titles = { disconnected: "Отключено", connecting: "Подключение…", connected: "Подключено", error: "Не удалось подключиться" };
  let title = titles[st];
  let sub = "";
  if (st === "disconnected") sub = "Нажмите, чтобы подключиться";
  if (st === "connecting") sub = "Запускаем туннель";
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
  $("status-sub").hidden = !sub || st === "connected" && !serviceIssue;
  const copyable = serviceIssue && !!state.error;
  $("status-sub").classList.toggle("copyable", copyable);
  $("status-sub").title = copyable ? "Нажмите, чтобы скопировать" : "";

  $("error-box").hidden = !failed;
  $("error-text").textContent = state.error || "Не удалось подключиться";

  $("speed").hidden = st !== "connected" || serviceIssue;
  $("down").textContent = speed(state.down);
  $("up").textContent = speed(state.up);
  $("uptime").textContent = elapsed(validDate(state.connectedAt) || new Date());

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
    setBadge($("corp-badge"), "on", "работает");
  } else {
    $("corp-sub").textContent = "OpenVPN · " + (corp.detail || "подключение…");
    // «подключение…» и «переподключение…» — ожидание, а не ошибка.
    const broken = corp.detail && !corp.detail.endsWith("…");
    setBadge($("corp-badge"), broken ? "bad" : "wait", broken ? "ошибка" : "ждём");
  }

  // Зарубежные сайты
  const px = state.proxy;
  if (!px.enabled) {
    $("proxy-sub").replaceChildren("Не настроено · добавьте подписку");
    setBadge($("proxy-badge"), null, "");
  } else {
    const labels = serverLabels(px.servers || []);
    const name = st === "connected" && px.current ? px.current : px.selected;
    const server = name && name !== "auto" ? labels.find(s => s.name === name) : null;
    let text;
    if (server) text = server.label;
    else if (name && name !== "auto") text = "Сервер";
    else if (labels.length > 1) text = `VLESS · автовыбор из ${labels.length} ${plural(labels.length, "сервера", "серверов", "серверов")}`;
    else text = labels[0]?.label || "VLESS";
    if (st === "connected" && px.delay > 0) text += ` · ${px.delay} мс`;
    if (st === "connected" && px.selected === "auto" && labels.length > 1) text += " · авто";
    const label = el("span", "", text);
    if (server) $("proxy-sub").replaceChildren(flag(server.code, "flag"), label);
    else $("proxy-sub").replaceChildren(label);
    if (st === "connected") {
      const checks = px.checks || [];
      const ok = checks.some(c => c.ok);
      setBadge($("proxy-badge"), checks.length ? (ok ? "on" : "bad") : "wait", checks.length ? (ok ? "доступен" : "нет связи") : "проверка");
    }
    else if (st === "connecting") setBadge($("proxy-badge"), "wait", "ждём");
    else setBadge($("proxy-badge"), "", "выкл");
  }

  $("direct-sub").textContent = settings && !settings.russiaDirect
    ? "Только локальная сеть"
    : "Российские сайты и локальная сеть";

  if (!$("sheet").hidden) renderServers();
  renderChecks();
  renderUsage();
  renderLinkInfo();
}

function renderChecks() {
  const list = $("service-checks");
  list.replaceChildren();
  const connected = state?.status === "connected";
  $("checks-block").hidden = !state?.proxy.enabled || !connected;
  $("btn-check-now").disabled = !connected;
  const checks = state?.proxy.checks || [];
  for (const check of checks) {
    const tile = el("div", "tile");
    tile.append(
      el("div", "tile-name", check.name),
      el("div", "tile-value " + (check.ok ? "ok" : "bad"), check.ok ? `${check.delay} мс` : "нет"),
    );
    tile.title = check.ok ? `${check.name}: ${check.delay} мс` : `${check.name}: нет ответа`;
    list.append(tile);
  }
  if (!checks.length) list.append(el("div", "tiles-empty", "Проверяем доступ…"));
  $("checks-time").textContent = checks.length
    ? "в " + new Date(checks[0].checkedAt).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" })
    : "";
}

function renderUsage() {
  const px = state?.proxy;
  const visible = !!px?.enabled && isSubscription();
  $("usage").hidden = !visible;
  if (!visible) return;
  const status = subscriptionStatus();
  const expiry = $("subscription-expiry-main");
  expiry.textContent = status.text;
  expiry.className = "subscription-expiry " + status.className;
  expiry.title = status.title;
  const hasTraffic = px.total > 0;
  $("usage-traffic").textContent = hasTraffic ? `${size(px.used)} из ${size(px.total)}` : "";
  $("usage-progress").hidden = !hasTraffic;
  if (hasTraffic) {
    const percent = Math.min(100, Math.round(px.used / px.total * 100));
    $("usage-progress-fill").style.width = percent + "%";
    $("usage-progress").setAttribute("aria-valuenow", percent);
  }
}

setInterval(() => {
  if (state && state.status === "connected") {
    $("uptime").textContent = elapsed(validDate(state.connectedAt) || new Date());
  }
}, 1000);

$("power").addEventListener("click", () => {
  if (onboardingVisible()) {
    $("ob-link").focus();
    return;
  }
  svc("Toggle").catch(showError);
});
$("btn-retry").addEventListener("click", () => svc("Toggle").catch(showError));
$("btn-error-copy").addEventListener("click", () => copy(state?.error));

$("route-corp").addEventListener("click", () => showPage("settings"));
$("route-proxy").addEventListener("click", () => {
  if (state && state.proxy.servers && state.proxy.servers.length > 1) openSheet();
  else showPage("settings");
});

// ---------- первый запуск ----------

// Ссылка из первого экрана сохраняется сразу: подтверждать нечего.
async function saveLinkNow(value) {
  const link = value.trim();
  if (!link) { $("ob-link").focus(); return; }
  try {
    await svc("SaveSettings", { ...(savedSettings || settings), link });
    if (draft) draft.link = link;
    $("ob-link").value = "";
    await reloadSettings();
    showToast("Подписка добавлена", "info");
  } catch (e) { showError(e); }
}

$("ob-link-form").addEventListener("submit", (e) => {
  e.preventDefault();
  saveLinkNow($("ob-link").value);
});
$("ob-paste").addEventListener("click", async () => {
  try {
    const text = (await Clipboard.Text()).trim();
    if (!text) return showError("Буфер обмена пуст");
    $("ob-link").value = text;
    await saveLinkNow(text);
  } catch (e) { showError(e); }
});
$("ob-browse").addEventListener("click", chooseOVPN);

// ---------- выбор сервера ----------

function serverButton(item) {
  const px = state.proxy;
  const selected = px.selected === item.name;
  const btn = el("button", "server" + (item.auto ? " auto" : "") + (selected ? " selected" : ""));
  btn.setAttribute("aria-pressed", String(selected));
  btn.title = item.auto ? "Самый быстрый по HTTP-проверке YouTube" : item.name;
  if (item.auto) {
    const text = el("div", "card-text");
    text.append(el("div", "card-title", item.label), el("div", "card-sub", item.sub));
    btn.append(html("div", "auto-icon", icons.bolt), text);
  } else {
    const quality = item.delay > 0 ? (item.delay < 150 ? "good" : item.delay > 400 ? "slow" : "mid") : "";
    const bars = html("span", "bars " + quality, "<span></span><span></span><span></span>");
    bars.setAttribute("aria-hidden", "true");
    const ping = el("span", "server-ping" + (quality === "good" || quality === "slow" ? " " + quality : ""),
      item.delay > 0 ? `${item.delay} мс` : "—");
    btn.append(flag(item.code, "flag-lg"), el("span", "server-name", item.label), bars, ping);
  }
  if (selected) btn.insertAdjacentHTML("beforeend", icons.check);
  btn.addEventListener("click", async () => {
    // Сервер переключается сразу, подтверждать не нужно.
    btn.disabled = true;
    try { await svc("SelectServer", item.name); closeSheet(); }
    catch (err) { showError(err); }
    finally { btn.disabled = false; }
  });
  return btn;
}

function renderServers() {
  const list = $("server-list");
  list.replaceChildren();
  const px = state.proxy;
  const labels = serverLabels(px.servers || []);
  $("sheet-sub").textContent = `${labels.length} ${plural(labels.length, "сервер", "сервера", "серверов")}`;
  const current = px.selected === "auto" && state.status === "connected"
    ? labels.find(s => s.name === px.current) : null;
  list.append(serverButton({
    name: "auto", auto: true, label: "Автовыбор",
    sub: current ? "Самый быстрый сейчас: " + current.label : "Самый быстрый по проверке YouTube",
  }));
  list.append(el("div", "sheet-label", "Вручную"));
  for (const server of labels) list.append(serverButton(server));
}

function openSheet() {
  renderServers();
  $("sheet").hidden = false;
}

function closeSheet() {
  $("sheet").hidden = true;
}

$("btn-sheet-close").addEventListener("click", closeSheet);
$("sheet").addEventListener("click", (e) => { if (e.target === $("sheet")) closeSheet(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeSheet(); });

async function runTest(btn) {
  btn.disabled = true;
  btn.classList.add("spinning");
  try { await svc("TestServers"); } catch (err) { showError(err); }
  finally { btn.disabled = false; btn.classList.remove("spinning"); }
}
$("btn-ping").addEventListener("click", () => runTest($("btn-ping")));
$("btn-check-now").addEventListener("click", () => runTest($("btn-check-now")));

// ---------- настройки ----------

function renderSettings() {
  if (!settings) return;
  if (document.activeElement !== $("link")) $("link").value = settings.link || "";
  $("opt-russia").checked = settings.russiaDirect;
  $("opt-autostart").checked = settings.autostart;
  $("opt-connect").checked = settings.connectOnStart;
  $("opt-tray").checked = settings.closeToTray;

  // Статус обновления сервис дописывает в конец строки версии.
  const [versionTitle, ...versionRest] = version.split(" · ");
  $("version").textContent = versionTitle || "";
  $("version-sub").textContent = versionRest.join(" · ");
  $("version-sub").hidden = versionRest.length === 0;

  const loaded = !!ovpn?.loaded;
  $("ovpn-file").hidden = !loaded;
  $("ovpn-pick").hidden = loaded;
  $("ovpn-name").textContent = loaded ? ovpn.name : "";
  $("ovpn-server").textContent = loaded ? (ovpn.error || ovpn.server) : "";
  $("ovpn-server").classList.toggle("bad", loaded && !!ovpn.error);
  $("btn-ovpn-remove").hidden = !loaded;
  $("ovpn-remove-divider").hidden = !loaded;
  $("ovpn-cert").hidden = !loaded || ovpn.needsAuth || !!ovpn.error;
  $("ovpn-auth").hidden = !loaded || !ovpn.needsAuth;
  $("domains-block").hidden = !loaded;
  if (document.activeElement !== $("ovpn-user")) $("ovpn-user").value = settings.ovpnUsername || "";
  if (document.activeElement !== $("ovpn-pass")) $("ovpn-pass").value = settings.ovpnPassword || "";

  const chips = $("chips");
  chips.querySelectorAll(".chip").forEach((c) => c.remove());
  for (const domain of settings.corpDomains || []) {
    const chip = el("div", "chip");
    chip.append(domain);
    const del = html("button", "", icons.close);
    del.setAttribute("aria-label", "Удалить " + domain);
    del.addEventListener("click", () => save({ corpDomains: settings.corpDomains.filter((d) => d !== domain) }));
    chip.append(del);
    chips.insertBefore(chip, $("domain-form"));
  }
  renderLinkInfo();
}

function renderLinkInfo() {
  const info = $("link-info");
  const stats = $("sub-stats");
  const message = $("subscription-expiry");
  stats.hidden = true;
  message.hidden = true;
  if (!state || !settings || !settings.link) { info.hidden = true; return; }
  const px = state.proxy;

  if (isSubscription()) {
    const status = subscriptionStatus();
    const expire = validDate(px.expire);
    stats.hidden = false;
    $("stat-servers").textContent = px.servers?.length || "—";
    $("stat-traffic").textContent = px.total > 0 ? `${size(px.used)} / ${size(px.total)}` : "—";
    const expireEl = $("stat-expire");
    expireEl.textContent = expire ? expire.toLocaleDateString("ru-RU", { day: "numeric", month: "long" }) : "—";
    expireEl.className = "stat-value " + status.className;
    expireEl.title = status.title;
    const text = status.message || (!expire && validDate(px.updated) ? status.text : "");
    message.hidden = !text;
    message.textContent = text;
  }

  const parts = [];
  if (px.title) parts.push(px.title);
  if (!isSubscription() && px.servers?.length) parts.push(px.servers.length === 1 ? "один сервер" : `серверов: ${px.servers.length}`);
  if (px.outdated) parts.push("используются сохранённые данные");
  info.hidden = parts.length === 0;
  info.textContent = parts.join(" · ");
  info.classList.toggle("bad", !!px.outdated);
}

function updateDirty() {
  app.classList.toggle("dirty", !!draft && !$("page-settings").hidden);
}

async function save(patch) {
  if (!savedSettings) savedSettings = { ...settings };
  draft = { ...(draft || settings), ...patch };
  settings = draft;
  $("settings-actions").hidden = false;
  const impact = $("settings-impact");
  impact.hidden = state?.status !== "connected";
  impact.textContent = "VPN переподключится";
  updateDirty();
  renderSettings();
}

function clearDraft() {
  draft = null; savedSettings = null;
  $("settings-actions").hidden = true;
  updateDirty();
}

$("btn-apply").addEventListener("click", async () => {
  if (!draft) return;
  const btn = $("btn-apply"); btn.disabled = true;
  try {
    await svc("SaveSettings", draft);
    previousSettings = savedSettings;
    clearDraft();
    $("btn-settings-undo").hidden = false;
    await reloadSettings();
    showToast("Настройки применены", "info");
  } catch (e) {
    showError(e);
  } finally { btn.disabled = false; }
});
$("btn-discard").addEventListener("click", async () => {
  clearDraft();
  await reloadSettings();
});
$("btn-settings-undo").addEventListener("click", async () => {
  if (!previousSettings) return;
  try {
    await svc("SaveSettings", previousSettings);
    previousSettings = null;
    clearDraft();
    $("btn-settings-undo").hidden = true;
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

async function chooseOVPN() {
  try {
    const info = await svc("ChooseOVPN");
    if (!info) return;
    ovpn = info;
    await reloadSettings();
    showToast("Конфигурация OpenVPN загружена", "info");
  } catch (e) { showError(e); }
}

async function loadOVPN(path, btn) {
  btn.disabled = true;
  try {
    ovpn = await svc("LoadOVPN", path);
    $("ovpn-path").value = "";
    await reloadSettings();
    showToast("Конфигурация OpenVPN загружена", "info");
  } catch (err) { showError(err); }
  finally { btn.disabled = false; }
}

$("btn-ovpn").addEventListener("click", chooseOVPN);
$("btn-ovpn-browse").addEventListener("click", chooseOVPN);
$("ovpn-path-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const path = $("ovpn-path").value.trim();
  if (!path) { $("ovpn-path").focus(); return; }
  await loadOVPN(path, $("btn-ovpn-load"));
});

function foundProfile(profile) {
  const row = el("div", "found");
  const text = el("div", "card-text");
  const path = el("div", "card-sub", profile.path);
  path.title = profile.path;
  text.append(el("div", "card-title", profile.name), path);
  const use = el("button", "btn primary compact", "Использовать");
  use.type = "button";
  use.setAttribute("aria-label", "Использовать " + profile.name);
  use.addEventListener("click", () => loadOVPN(profile.path, use));
  row.insertAdjacentHTML("afterbegin", icons.file);
  row.append(text, use);
  return row;
}

function renderFound() {
  const settingsList = $("ovpn-found");
  const onboardingList = $("ob-found");
  for (const list of [settingsList, onboardingList]) {
    list.replaceChildren();
    if (searching) list.append(el("div", "hint", "Ищем профили OpenVPN…"));
    else for (const profile of profiles || []) list.append(foundProfile(profile));
  }
  if (!searching && profiles && !profiles.length) {
    settingsList.append(el("div", "hint", "Профили не найдены. Выберите файл вручную."));
  }
  settingsList.hidden = profiles === null && !searching;
  // На первом экране пустой результат не показываем: есть кнопка выбора файла.
  onboardingList.hidden = !searching && !profiles?.length;
  const btn = $("btn-ovpn-find");
  btn.disabled = searching;
  btn.textContent = searching ? "Ищем…" : profiles ? "Повторить поиск" : "Найти на компьютере";
}

async function findOVPN() {
  searching = true;
  renderFound();
  try {
    profiles = await svc("FindOVPN");
  } catch (err) {
    profiles = profiles || [];
    showError(err);
  } finally {
    searching = false;
    renderFound();
  }
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
  $("btn-password").setAttribute("aria-label", visible ? "Скрыть пароль" : "Показать пароль");
  $("btn-password").setAttribute("aria-pressed", String(visible));
});

$("btn-diagnostics").addEventListener("click", () => {
  const block = $("diagnostics-block");
  const open = block.hidden;
  block.hidden = !open;
  $("btn-diagnostics").setAttribute("aria-expanded", String(open));
  if (!open) return;
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
  document.querySelectorAll(".nav-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.page === name);
    if (b.dataset.page === name) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  if (name === "settings" && ovpn && !ovpn.loaded && profiles === null && !searching) findOVPN();
  updateDirty();
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
  if (state?.service && state.error) copy(state.error);
});
$("link-info").addEventListener("click", () => {
  if ($("link-info").classList.contains("bad")) copy($("link-info").textContent);
});

document.addEventListener("contextmenu", (e) => {
  if (!(e.target instanceof HTMLInputElement)) e.preventDefault();
});

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

// ---------- старт ----------

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
  } catch (e) {
    showError(e);
  }
})();
