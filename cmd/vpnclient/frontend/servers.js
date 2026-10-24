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
  ["RU", "Россия", /🇷🇺|\b(ru|russia|moscow)\b|росси|москв/i],
  ["BR", "Бразилия", /🇧🇷|\b(br|brazil|sao paulo)\b|бразил/i],
  ["LV", "Латвия", /🇱🇻|\b(lv|latvia|riga)\b|латви/i],
  ["KZ", "Казахстан", /🇰🇿|\b(kz|kazakhstan|almaty|astana)\b|казахстан|алмат|астан/i],
];

export function serverLabels(servers) {
  return servers.map((server, index) => {
    // UUID и адреса не используются как географические подсказки.
    const source = server.name.replace(/\b[\w.-]+\.[a-z]{2,}\b|[a-f0-9]{8}-[a-f0-9-]{27,}|\b\d+(?:\.\d+){3}\b/gi, " ").replace(/_/g, " ");
    const matches = countries.filter(([, , pattern]) => pattern.test(source));
    const country = matches.length === 1 ? matches[0] : null;
    const base = country ? country[1] : "Сервер";
    const cities = [[/amsterdam|амстердам/i, "Амстердам"], [/frankfurt|франкфурт/i, "Франкфурт"], [/berlin|берлин/i, "Берлин"], [/helsinki|хельсинки/i, "Хельсинки"], [/paris|париж/i, "Париж"], [/london|лондон/i, "Лондон"], [/stockholm|стокгольм/i, "Стокгольм"], [/tokyo|токио/i, "Токио"]];
    const city = cities.find(([pattern]) => pattern.test(source))?.[1];
    const cleaned = source.replace(/\b(vless|reality|xtls|tcp|udp|grpc|ws|tls|vision)\b/gi, "").replace(/[|¦]+/g, " · ").replace(/\s+/g, " ").trim();
    // Уточнения через «·» («Мост», «Hysteria») отличают точки входа одной
    // страны: без них остались бы безликие «Германия · 1» и «Германия · 2».
    const extras = country ? cleaned.split("·").slice(1).map(part => part.trim())
      .filter(part => part && !country[2].test(part) && !cities.some(([pattern]) => pattern.test(part))) : [];
    const label = country ? [base, city, ...extras].filter(Boolean).join(" · ") : (cleaned || "Узел без названия");
    return { ...server, label, code: country?.[0] || "", index: index + 1 };
  }).map((server, index, all) => {
    const duplicates = all.filter(s => s.label === server.label);
    return duplicates.length > 1 ? { ...server, label: `${server.label} · ${duplicates.indexOf(server) + 1}` } : server;
  });
}

const stripes = {
  NL: ["#ae1c28", "#fff", "#21468b"], DE: ["#111", "#d00", "#ffce00"],
  FR: ["#0055a4", "#fff", "#ef4135"], TR: ["#e30a17"], JP: ["#fff"],
  PL: ["#fff", "#dc143c"], FI: ["#fff"], SE: ["#006aa7"], CH: ["#d52b1e"],
  US: ["#b22234", "#fff", "#b22234", "#fff", "#b22234", "#fff", "#b22234"],
  GB: ["#012169"], SG: ["#ef3340", "#fff"],
  RU: ["#fff", "#0039a6", "#d52b1e"], LV: ["#9e3039", "#9e3039", "#fff", "#9e3039", "#9e3039"],
  KZ: ["#00afca"], BR: ["#009c3b"],
};

// Локальная SVG-иконка, код страны не зависит от поддержки emoji в Windows.
export function serverIcon(code = "") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 32 24");
  svg.setAttribute("width", "32"); svg.setAttribute("height", "32");
  svg.setAttribute("aria-hidden", "true");
  const colors = stripes[code];
  if (!colors) {
    svg.innerHTML = '<circle cx="16" cy="12" r="10"/><path d="M6 12h20M16 2c6 5 6 15 0 20M16 2c-6 5-6 15 0 20"/>';
    return svg;
  }
  svg.style.stroke = "none";
  svg.innerHTML = colors.map((fill, i) => code === "FR"
    ? `<rect x="${i * 32 / colors.length}" y="2" width="${32 / colors.length + .1}" height="20" fill="${fill}"/>`
    : `<rect x="0" y="${2 + i * 20 / colors.length}" width="32" height="${20 / colors.length + .1}" fill="${fill}"/>`).join("");
  const cross = (color, width, x = 11) => `<path d="M${x} 2v20M0 12h32" stroke="${color}" stroke-width="${width}" stroke-linecap="butt"/>`;
  if (code === "FI" || code === "SE") svg.innerHTML += cross(code === "FI" ? "#003580" : "#fecc00", 5);
  if (code === "CH") svg.innerHTML += '<path d="M16 6v12M10 12h12" stroke="#fff" stroke-width="4" stroke-linecap="butt"/>';
  if (code === "JP") svg.innerHTML += '<circle cx="16" cy="12" r="6" fill="#bc002d"/>';
  if (code === "GB") svg.innerHTML += '<path d="M0 2l32 20M32 2L0 22" stroke="#fff" stroke-width="5"/><path d="M0 2l32 20M32 2L0 22" stroke="#c8102e" stroke-width="2"/>' + cross("#fff", 8, 16) + cross("#c8102e", 4, 16);
  if (code === "US") svg.innerHTML += '<rect x="0" y="2" width="14" height="11" fill="#3c3b6e"/><path d="M3 5h1m3 0h1m3 0h1M3 8h1m3 0h1m3 0h1" stroke="#fff" stroke-width="1.5"/>';
  if (code === "TR" || code === "SG") svg.innerHTML += `<circle cx="10" cy="${code === "SG" ? 7 : 12}" r="${code === "SG" ? 4 : 6}" fill="#fff"/><circle cx="12" cy="${code === "SG" ? 6 : 11}" r="${code === "SG" ? 3.4 : 5}" fill="${colors[0]}"/>`;
  if (code === "KZ") svg.innerHTML += '<circle cx="16" cy="11" r="4" fill="#fec50c"/>';
  if (code === "BR") svg.innerHTML += '<path d="M16 4l13 8-13 8-13-8z" fill="#fedf00"/><circle cx="16" cy="12" r="4.5" fill="#002776"/>';
  return svg;
}
