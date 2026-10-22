import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";

const source = await readFile(new URL("./servers.js", import.meta.url), "utf8");
const { serverLabels } = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
const names = ["🇳🇱 Netherlands VLESS REALITY 01", "NL premium", "node-42.example.com", "192.0.2.1", "Germany Frankfurt", "NL DE transit"];
const result = serverLabels(names.map(name => ({ name, delay: 50 })));
assert.deepEqual(result.map(s => s.label), ["Нидерланды · 1", "Нидерланды · 2", "Сервер 3", "Сервер 4", "Германия · 1", "Сервер 6"]);
assert.deepEqual(result.map(s => s.name), names);
assert.equal(result[0].code, "NL");
assert.equal(result[2].code, "");
console.log("PASS: названия, дубликаты, неизвестная и неоднозначная география, сохранение ID");
