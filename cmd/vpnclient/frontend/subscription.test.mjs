import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
const source = await readFile(new URL("./subscription.js", import.meta.url), "utf8");
const { subscriptionExpiry } = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
const now = new Date("2030-01-01T12:00:00Z");
assert.equal(subscriptionExpiry("2030-02-01T12:00:00Z", now).expired, false);
assert.equal(subscriptionExpiry("2029-01-01T12:00:00Z", now).expired, true);
assert.equal(subscriptionExpiry("2030-01-02T12:00:00Z", now).soon, true);
for (const value of [undefined, "invalid", "0001-01-01T00:00:00Z"]) {
  assert.equal(subscriptionExpiry(value, now).text, "Провайдер не указал срок подписки");
}
console.log("PASS: срок подписки, истечение, скорое окончание, отсутствие даты");
