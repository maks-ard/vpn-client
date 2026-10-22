// География определяется только из явного названия, без запросов к сторонним API.
const countries = [
  ["NL", "Нидерланды", /🇳🇱|\b(nl|netherlands|holland|amsterdam)\b|нидерланд|голланд|амстердам/i],
  ["DE", "Германия", /🇩🇪|\b(de|germany|german|frankfurt|berlin)\b|герман|франкфурт|берлин/i],
  ["FI", "Финляндия", /🇫🇮|\b(fi|finland|helsinki)\b|финлян|хельсинки/i],
  ["FR", "Франция", /🇫🇷|\b(fr|france|paris)\b|франци|париж/i],
  ["US", "США", /🇺🇸|\b(us|usa|united states|new york)\b|сша|нью-йорк/i],
  ["GB", "Великобритания", /🇬🇧|\b(gb|uk|united kingdom|london)\b|британи|лондон/i],
  ["SE", "Швеция", /🇸🇪|\b(se|sweden|stockholm)\b|швеци|стокгольм/i],
  ["CH", "Швейцария", /🇨🇭|\b(ch|switzerland|zurich)\b|швейцар|цюрих/i],
  ["TR", "Турция", /🇹🇷|\b(tr|turkey|turkiye|istanbul)\b|турци|стамбул/i],
  ["JP", "Япония", /🇯🇵|\b(jp|japan|tokyo)\b|япони|токио/i],
  ["SG", "Сингапур", /🇸🇬|\b(sg|singapore)\b|сингапур/i],
  ["PL", "Польша", /🇵🇱|\b(pl|poland|warsaw)\b|польш|варшав/i],
];

export function serverLabels(servers) {
  const counts = new Map();
  return servers.map((server, index) => {
    // UUID и адреса не используются как географические подсказки.
    const source = server.name.replace(/\b[\w.-]+\.[a-z]{2,}\b|[a-f0-9]{8}-[a-f0-9-]{27,}|\b\d+(?:\.\d+){3}\b/gi, " ");
    const matches = countries.filter(([, , pattern]) => pattern.test(source));
    const country = matches.length === 1 ? matches[0] : null;
    const base = country ? country[1] : "Сервер";
    const n = (counts.get(base) || 0) + 1;
    counts.set(base, n);
    return { ...server, label: country ? `${base} · ${n}` : `Сервер ${index + 1}`, code: country?.[0] || "", index: index + 1 };
  });
}

// Локальная SVG-иконка, код страны не зависит от поддержки emoji в Windows.
export function serverIcon(code = "") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 32 32");
  svg.setAttribute("width", "32"); svg.setAttribute("height", "32");
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = code
    ? '<rect x="1" y="1" width="30" height="30" rx="8" fill="var(--surface-2)" stroke="none"/><text x="16" y="20" text-anchor="middle" fill="currentColor" stroke="none" font-size="11" font-family="Segoe UI, sans-serif" font-weight="600"></text>'
    : '<circle cx="16" cy="16" r="11"/><path d="M5 16h22M16 5c7 6 7 16 0 22M16 5c-7 6-7 16 0 22"/>';
  if (code) svg.querySelector("text").textContent = code;
  return svg;
}
