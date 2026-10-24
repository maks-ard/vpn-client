import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";

const source = await readFile(new URL("./servers.js", import.meta.url), "utf8");
const { serverLabels } = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
const names = ["🇳🇱 Netherlands VLESS REALITY 01", "NL premium", "node-42.example.com", "192.0.2.1", "Germany Frankfurt", "NL DE transit"];
const result = serverLabels(names.map(name => ({ name, delay: 50 })));
assert.deepEqual(result.map(s => s.label), ["Нидерланды · 1", "Нидерланды · 2", "Узел без названия · 1", "Узел без названия · 2", "Германия · Франкфурт", "NL DE transit"]);
assert.deepEqual(result.map(s => s.name), names);
assert.equal(result[0].code, "NL");
assert.equal(result[2].code, "");
assert.equal(serverLabels([{name:"DE_Frankfurt_REALITY"}])[0].label, "Германия · Франкфурт");
assert.equal(serverLabels([{name:"Мой быстрый узел"}])[0].label, "Мой быстрый узел");
// Записи Remnawave: страна и уточнение точки входа.
const remna = serverLabels(["🇩🇪 Германия", "🇩🇪 Германия · Мост", "🇳🇱 Нидерланды · Hysteria", "🇰🇿 Казахстан · Мост", "🇷🇺 Россия", "🇩🇪 Германия · Франкфурт"].map(name => ({ name })));
assert.deepEqual(remna.map(s => s.label), ["Германия", "Германия · Мост", "Нидерланды · Hysteria", "Казахстан · Мост", "Россия", "Германия · Франкфурт"]);
assert.deepEqual(remna.map(s => s.code), ["DE", "DE", "NL", "KZ", "RU", "DE"]);
console.log("PASS: названия, дубликаты, неизвестная и неоднозначная география, сохранение ID");
