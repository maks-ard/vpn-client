// Чистая логика вкладки «Правила»: списки категорий, порядок, подписи.
// Без DOM, чтобы проверяться обычными тестами (rules-model.test.mjs).

export const DIRECTIONS = {
  corp: "OpenVPN",
  proxy: "VLESS",
  auto: "Авто",
  direct: "Прямо",
  block: "Блок",
};

// Реклама либо блокируется, либо не трогается; остальное можно вести куда угодно.
export function presetOptions(id) {
  return id === "ads" ? ["block", "auto"] : ["proxy", "auto", "direct"];
}

export function newCategoryId(random = Math.random) {
  let hex = "";
  for (let i = 0; i < 8; i++) hex += Math.floor(random() * 16).toString(16);
  return "c-" + hex;
}

export const list = (cats) => (Array.isArray(cats) ? cats : []);

export function presetAction(cats, id) {
  return list(cats).find((c) => c.preset && c.id === id)?.action || "auto";
}

// Свои категории стоят выше готовых, готовые идут в порядке каталога.
// Так приоритет понятен: то, что пользователь создал, перебивает общие наборы.
export function normalizeOrder(cats, catalogIds) {
  const rank = (id) => {
    const i = catalogIds.indexOf(id);
    return i < 0 ? catalogIds.length : i;
  };
  const own = list(cats).filter((c) => !c.preset);
  const presets = list(cats).filter((c) => c.preset).sort((a, b) => rank(a.id) - rank(b.id));
  return [...own, ...presets];
}

// «Авто» для готовой категории не хранится: запись с auto ничего не меняет.
export function setPreset(cats, id, action, catalogIds) {
  const rest = list(cats).filter((c) => !(c.preset && c.id === id));
  if (action !== "auto") rest.push({ id, preset: true, action });
  return normalizeOrder(rest, catalogIds);
}

export function findCategory(cats, id) {
  return list(cats).find((c) => c.id === id);
}

export function upsertCustom(cats, category, catalogIds) {
  const rest = list(cats).filter((c) => c.id !== category.id);
  const index = list(cats).findIndex((c) => c.id === category.id);
  const own = rest.filter((c) => !c.preset);
  own.splice(index >= 0 ? Math.min(index, own.length) : own.length, 0, category);
  return normalizeOrder([...own, ...rest.filter((c) => c.preset)], catalogIds);
}

export function removeCategory(cats, id) {
  return list(cats).filter((c) => c.id !== id);
}

// Сдвиг своей категории вверх (delta -1) или вниз (+1) среди своих.
export function moveCustom(cats, id, delta, catalogIds) {
  const own = list(cats).filter((c) => !c.preset);
  const from = own.findIndex((c) => c.id === id);
  const to = from + delta;
  if (from < 0 || to < 0 || to >= own.length) return list(cats);
  [own[from], own[to]] = [own[to], own[from]];
  return normalizeOrder([...own, ...list(cats).filter((c) => c.preset)], catalogIds);
}

export function configuredCount(cats, russiaDirect) {
  return list(cats).filter((c) => c.action !== "auto").length + (russiaDirect ? 1 : 0);
}

export function plural(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
}

export const rulesWord = (n) => `${n} ${plural(n, "правило", "правила", "правил")}`;

export const RULE_TYPES = {
  domain: "домен",
  keyword: "часть адреса",
  cidr: "подсеть",
  process: "программа",
  ruleset: "набор .srs",
};

// Результат проверки адреса в виде, готовом для показа.
export function verdictView(verdict, proxyName) {
  const kinds = {
    corp: { title: "Через OpenVPN", sub: "Корпоративная сеть" },
    proxy: { title: "Через VLESS", sub: proxyName ? "Сервер: " + proxyName : "Зарубежный сервер" },
    direct: { title: "Напрямую", sub: "Без VPN" },
    block: { title: "Заблокировано", sub: "Соединение будет отклонено" },
  };
  const kind = kinds[verdict.action] || kinds.direct;
  return {
    action: verdict.action,
    title: kind.title,
    sub: kind.sub,
    why: verdict.rule
      ? "Сработало правило: " + verdict.rule
      : "Ни одно правило не подошло, так идёт весь остальной трафик",
    notes: verdict.notes || [],
    target: verdict.target,
  };
}
