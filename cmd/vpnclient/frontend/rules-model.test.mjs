import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";

const source = await readFile(new URL("./rules-model.js", import.meta.url), "utf8");
const m = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));

const catalog = ["gov-bank-ru", "ads", "video", "social", "ai", "dev", "games"];
const custom = (id, action = "direct") => ({ id, name: id, action, rules: [] });

// Готовая категория: «Авто» не хранится, остальное ставится по порядку каталога.
let cats = [];
cats = m.setPreset(cats, "social", "proxy", catalog);
cats = m.setPreset(cats, "ads", "block", catalog);
assert.deepEqual(cats.map((c) => c.id), ["ads", "social"]);
assert.equal(m.presetAction(cats, "social"), "proxy");
assert.equal(m.presetAction(cats, "video"), "auto");
cats = m.setPreset(cats, "social", "auto", catalog);
assert.deepEqual(cats.map((c) => c.id), ["ads"]);

// Свои категории выше готовых, порядок между своими сохраняется и меняется.
cats = m.upsertCustom(cats, custom("c-1"), catalog);
cats = m.upsertCustom(cats, custom("c-2"), catalog);
assert.deepEqual(cats.map((c) => c.id), ["c-1", "c-2", "ads"]);
cats = m.moveCustom(cats, "c-2", -1, catalog);
assert.deepEqual(cats.map((c) => c.id), ["c-2", "c-1", "ads"]);
assert.deepEqual(m.moveCustom(cats, "c-2", -1, catalog).map((c) => c.id), ["c-2", "c-1", "ads"], "выше первой не сдвигается");
assert.deepEqual(m.moveCustom(cats, "c-1", 1, catalog).map((c) => c.id), ["c-2", "c-1", "ads"], "ниже последней своей не сдвигается");
// Правка существующей не меняет её позицию.
cats = m.upsertCustom(cats, { ...custom("c-2"), name: "Другое" }, catalog);
assert.deepEqual(cats.map((c) => c.id), ["c-2", "c-1", "ads"]);
assert.equal(m.findCategory(cats, "c-2").name, "Другое");
assert.deepEqual(m.removeCategory(cats, "c-1").map((c) => c.id), ["c-2", "ads"]);

// Устойчивость к пустым значениям из старых настроек.
assert.deepEqual(m.list(null), []);
assert.equal(m.presetAction(undefined, "ads"), "auto");
assert.deepEqual(m.setPreset(null, "ads", "block", catalog), [{ id: "ads", preset: true, action: "block" }]);

// Счётчик настроенного: «Авто» не считается, российские сайты считаются.
assert.equal(m.configuredCount([custom("a"), custom("b", "auto")], false), 1);
assert.equal(m.configuredCount([], true), 1);

// Варианты направления для готовых категорий.
assert.deepEqual(m.presetOptions("ads"), ["block", "auto"]);
assert.deepEqual(m.presetOptions("video"), ["proxy", "auto", "direct"]);

// Идентификаторы подходят под проверку в Go: ^[a-z0-9][a-z0-9_-]{0,63}$.
for (let i = 0; i < 50; i++) assert.match(m.newCategoryId(), /^c-[0-9a-f]{8}$/);

// Подписи.
assert.equal(m.rulesWord(1), "1 правило");
assert.equal(m.rulesWord(3), "3 правила");
assert.equal(m.rulesWord(11), "11 правил");
assert.equal(m.rulesWord(21), "21 правило");
const v = m.verdictView({ action: "proxy", rule: "категория «Соцсети»", target: "t.me", notes: ["x"] }, "Нидерланды");
assert.equal(v.title, "Через VLESS");
assert.equal(v.sub, "Сервер: Нидерланды");
assert.match(v.why, /Соцсети/);
assert.match(m.verdictView({ action: "direct" }).why, /остальной трафик/);
assert.equal(m.verdictView({ action: "block" }).title, "Заблокировано");
assert.equal(m.verdictView({ action: "proxy" }).sub, "Зарубежный сервер");

console.log("PASS: правила: порядок, готовые категории, перемещение, подписи");
