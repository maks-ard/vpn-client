// Вкладка «Правила»: обзор, категории сайтов, редактор категории, проверка адреса.
// Правки идут в черновик настроек (save), применяются общей панелью «Применить».
import {
  DIRECTIONS, RULE_TYPES, presetOptions, newCategoryId, list, presetAction, setPreset,
  findCategory, upsertCustom, removeCategory, moveCustom, configuredCount, rulesWord, verdictView,
} from "./rules-model.js";

const icons = {
  back: '<svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path d="M15 6l-6 6 6 6"/></svg>',
  chevron: '<svg class="chevron" width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>',
  close: '<svg width="14" height="14" viewBox="0 0 12 12" aria-hidden="true"><path d="M2.5 2.5l7 7M9.5 2.5l-7 7"/></svg>',
  up: '<svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 15l6-6 6 6"/></svg>',
  down: '<svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>',
  grid: '<svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/></svg>',
  search: '<svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/></svg>',
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

export function createRules(ctx) {
  const { root, svc, getSettings, getPresets, getOvpn, getState, isDirty, save, showError, showToast } = ctx;
  let view = "overview";
  let editId = null;
  let confirmDelete = false;
  let probe = { target: "", result: null, error: "", busy: false };

  const catalogIds = () => getPresets().map((p) => p.id);
  const cats = () => list(getSettings()?.categories);
  const commit = (next) => save({ categories: next });

  function go(next, id = null) {
    view = next;
    editId = id;
    confirmDelete = false;
    render();
  }

  function seg(options, current, onPick, wide) {
    const box = el("div", "seg" + (wide ? " wide" : ""));
    box.setAttribute("role", "group");
    for (const action of options) {
      const on = action === current;
      const btn = el("button", on ? "on " + action : "", DIRECTIONS[action]);
      btn.type = "button";
      btn.setAttribute("aria-pressed", String(on));
      btn.addEventListener("click", () => { if (!on) onPick(action); });
      box.append(btn);
    }
    return box;
  }

  function subhead(title, back, extra) {
    const head = el("div", "subhead");
    const btn = html("button", "icon-btn boxed", icons.back);
    btn.type = "button";
    btn.setAttribute("aria-label", "Назад");
    btn.addEventListener("click", back);
    head.append(btn, el("h1", "page-title", title));
    if (extra) head.append(...extra);
    return head;
  }

  function navRow({ title, sub, count, onClick }) {
    const row = el("button", "list-row route");
    row.type = "button";
    const text = el("div", "card-text");
    text.append(el("div", "card-title", title));
    if (sub) text.append(el("div", "card-sub", sub));
    row.append(text);
    if (count !== undefined) row.append(el("span", "count", count));
    row.insertAdjacentHTML("beforeend", icons.chevron);
    row.addEventListener("click", onClick);
    return row;
  }

  function group(label, ...children) {
    const box = el("section", "group");
    if (label) box.append(el("div", "section-label", label));
    box.append(...children);
    return box;
  }

  function card(...rows) {
    const box = el("div", "card list");
    box.append(...rows);
    return box;
  }

  // ---------- обзор ----------

  function overview() {
    const s = getSettings();
    const state = getState();
    const configured = configuredCount(s.categories, s.russiaDirect);
    const vless = !s.proxyDisabled && (state?.proxy?.enabled || /^vless:|^https?:/i.test(s.link || ""));
    const rest = vless ? "через VLESS" : "напрямую";
    return [
      el("h1", "page-title pad", "Правила"),
      group("Общие правила", card(navRow({
        title: "Категории сайтов",
        sub: "Видео, соцсети, ИИ, игры и свои",
        count: configured ? String(configured) : "",
        onClick: () => go("categories"),
      }))),
      group("", card(navRow({
        title: "Проверить адрес",
        sub: "Куда пойдёт сайт или IP",
        onClick: () => go("check"),
      }))),
      el("p", "lead pad", "Всё остальное, что не попало ни в одну категорию, идёт " + rest + "."),
    ];
  }

  // ---------- категории ----------

  function presetRow(preset) {
    const row = el("div", "list-row static cat");
    const text = el("div", "card-text");
    text.append(el("div", "row-title", preset.title), el("div", "row-sub", preset.examples));
    row.append(text, seg(presetOptions(preset.id), presetAction(cats(), preset.id),
      (action) => commit(setPreset(cats(), preset.id, action, catalogIds()))));
    return row;
  }

  function russiaRow() {
    const s = getSettings();
    const row = el("div", "list-row static cat");
    const text = el("div", "card-text");
    text.append(el("div", "row-title", "Российские сайты"), el("div", "row-sub", ".ru, .рф, Яндекс, VK, банки"));
    row.append(text, seg(["auto", "direct"], s.russiaDirect ? "direct" : "auto", (a) => save({ russiaDirect: a === "direct" })));
    return row;
  }

  function categories() {
    const rows = [];
    if (getOvpn()?.loaded) {
      const n = list(getSettings().corpDomains).length;
      rows.push(navRow({
        title: "Корпоративная сеть",
        sub: `Системная · ${rulesWord(n)} · OpenVPN`,
        onClick: () => go("edit", "corp"),
      }));
    }
    rows.push(russiaRow());
    for (const c of cats().filter((c) => !c.preset)) {
      rows.push(navRow({
        title: c.name,
        sub: `${rulesWord(list(c.rules).length)} · ${DIRECTIONS[c.action] || c.action}`,
        onClick: () => go("edit", c.id),
      }));
    }
    for (const p of getPresets()) rows.push(presetRow(p));

    const add = el("button", "btn", "+ Своя категория");
    add.type = "button";
    add.addEventListener("click", () => {
      const category = { id: newCategoryId(), name: "Новая категория", action: "auto", rules: [] };
      commit(upsertCustom(cats(), category, catalogIds()));
      go("edit", category.id);
    });
    const imp = el("button", "btn ghost", "Импорт…");
    imp.type = "button";
    imp.addEventListener("click", async () => {
      try {
        const imported = await svc("ImportCategoryFile", cats());
        if (!imported) return;
        commit(upsertCustom(cats(), imported, catalogIds()));
        showToast("Категория добавлена: выберите, куда направлять её трафик", "info");
        go("edit", imported.id);
      } catch (e) { showError(e); }
    });
    const actions = el("div", "row");
    actions.append(add, imp);

    return [
      subhead("Категории сайтов", () => go("overview")),
      el("p", "lead pad", "Один выбор на целую группу сервисов. Свои категории проверяются раньше готовых."),
      card(...rows),
      actions,
      el("div", "hint pad", "Авто: как весь остальной трафик."),
    ];
  }

  // ---------- редактор ----------

  function ruleRow(tag, value, onDelete) {
    const row = el("div", "list-row static cat");
    const text = el("div", "card-text");
    const title = el("div", "row-title", value);
    title.title = value;
    text.append(title);
    const del = html("button", "icon-btn", icons.close);
    del.type = "button";
    del.setAttribute("aria-label", "Удалить " + value);
    del.addEventListener("click", onDelete);
    row.append(el("span", "tag", tag), text, del);
    return row;
  }

  function addForm({ placeholder, withType, onAdd }) {
    const form = el("form", "row");
    const input = el("input", "input");
    input.type = "text";
    input.placeholder = placeholder;
    input.spellcheck = false;
    input.autocomplete = "off";
    input.setAttribute("aria-label", placeholder);
    form.append(input);
    let select = null;
    if (withType) {
      select = el("select", "input select");
      select.setAttribute("aria-label", "Тип правила");
      select.append(new Option("Авто", ""));
      for (const [value, label] of Object.entries(RULE_TYPES)) select.append(new Option(label[0].toUpperCase() + label.slice(1), value));
      form.append(select);
    }
    const btn = el("button", "btn", "Добавить");
    btn.type = "submit";
    form.append(btn);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const value = input.value.trim();
      if (!value) { input.focus(); return; }
      btn.disabled = true;
      try { if (await onAdd(value, select?.value || "")) input.value = ""; }
      catch (err) { showError(err); }
      finally { btn.disabled = false; }
    });
    return form;
  }

  function corpEditor() {
    const domains = list(getSettings().corpDomains);
    const remove = (d) => save({ corpDomains: domains.filter((x) => x !== d) });
    return [
      subhead("Корпоративная сеть", () => go("categories")),
      el("p", "lead pad", "Домены, которые идут через OpenVPN. Поддомены включаются сами. Подсети и DNS-домены присылает сервер."),
      domains.length ? card(...domains.map((d) => ruleRow("домен", d, () => remove(d)))) : el("div", "hint pad", "Своих доменов нет."),
      addForm({
        placeholder: "Домен, например corp.example.com",
        withType: false,
        onAdd: async (value) => {
          const rule = await svc("ParseRule", "domain", value);
          if (!domains.includes(rule.value)) await save({ corpDomains: [...domains, rule.value] });
          return true;
        },
      }),
    ];
  }

  function customEditor(category) {
    const rules = list(category.rules);
    const update = (patch) => commit(upsertCustom(cats(), { ...category, ...patch }, catalogIds()));
    const own = cats().filter((c) => !c.preset);
    const index = own.findIndex((c) => c.id === category.id);

    const mover = (delta, icon, label) => {
      const btn = html("button", "icon-btn boxed", icon);
      btn.type = "button";
      btn.setAttribute("aria-label", label);
      btn.disabled = index + delta < 0 || index + delta >= own.length;
      btn.addEventListener("click", () => commit(moveCustom(cats(), category.id, delta, catalogIds())));
      return btn;
    };

    const name = el("input", "input");
    name.type = "text";
    name.id = "cat-name";
    name.value = category.name;
    name.maxLength = 64;
    name.addEventListener("change", () => {
      const value = name.value.trim();
      if (value) update({ name: value }); else name.value = category.name;
    });
    const nameBox = el("div", "stack-sm");
    const label = el("label", "field-label", "Название");
    label.htmlFor = "cat-name";
    nameBox.append(label, name);

    const directions = el("div", "stack-sm");
    directions.append(el("div", "field-title", "Куда направлять"));
    const dirSeg = seg(["corp", "proxy", "auto", "direct", "block"], category.action, (action) => update({ action }), true);
    if (!getOvpn()?.loaded) {
      const corpBtn = dirSeg.firstElementChild;
      corpBtn.disabled = category.action !== "corp";
      corpBtn.title = "Сначала загрузите профиль OpenVPN в настройках";
    }
    directions.append(dirSeg);
    if (category.action === "corp") {
      directions.append(el("div", "hint", "Категории с OpenVPN проверяются раньше локальной сети: иначе подсети вида 10.x ушли бы напрямую."));
    }

    const removeRule = (rule) => update({ rules: rules.filter((r) => !(r.type === rule.type && r.value === rule.value)) });
    const rulesBlock = [
      el("div", "section-label", "Правила · " + rules.length),
      rules.length ? card(...rules.map((r) => ruleRow(RULE_TYPES[r.type] || r.type, r.value, () => removeRule(r)))) : el("div", "hint pad", "Правил пока нет. Добавьте домен, подсеть или программу."),
      addForm({
        placeholder: "Домен, подсеть, часть адреса или .exe",
        withType: true,
        onAdd: async (value, type) => {
          const rule = await svc("ParseRule", type, value);
          if (rules.some((r) => r.type === rule.type && r.value === rule.value)) {
            showToast("Такое правило уже есть", "info");
            return true;
          }
          await update({ rules: [...rules, rule] });
          return true;
        },
      }),
    ];
    if (rules.some((r) => r.type === "keyword")) {
      rulesBlock.push(el("div", "hint pad", "«Часть адреса» ловит любой домен с этими буквами: slack найдёт и slack.com, и myslackbot.net. Домен точнее."));
    }
    if (rules.some((r) => r.type === "ruleset")) {
      rulesBlock.push(el("div", "hint pad", "Набор .srs скачивается при подключении. Если ссылка не открывается, подключение может не подняться."));
    }

    const exportBtn = el("button", "btn", "Экспорт в файл…");
    exportBtn.type = "button";
    exportBtn.addEventListener("click", async () => {
      try { await svc("ExportCategoryFile", { ...category, rules }); showToast("Файл сохранён", "info"); }
      catch (e) { showError(e); }
    });
    const delBtn = el("button", "btn ghost danger-text", confirmDelete ? "Точно удалить?" : "Удалить категорию");
    delBtn.type = "button";
    delBtn.addEventListener("click", () => {
      if (!confirmDelete) { confirmDelete = true; render(); return; }
      commit(removeCategory(cats(), category.id));
      go("categories");
    });
    const footer = el("div", "row between");
    footer.append(exportBtn, delBtn);

    return [
      subhead(category.name, () => go("categories"), [mover(-1, icons.up, "Выше"), mover(1, icons.down, "Ниже")]),
      nameBox,
      directions,
      ...rulesBlock,
      footer,
      el("div", "hint pad", "В файл попадают название и правила. Куда направлять, решает тот, кто импортирует."),
    ];
  }

  function editor() {
    if (editId === "corp") return corpEditor();
    const category = findCategory(cats(), editId);
    if (!category || category.preset) {
      // Категорию удалили или сбросили черновик: возвращаемся к списку.
      view = "categories";
      editId = null;
      return categories();
    }
    return customEditor(category);
  }

  // ---------- проверка адреса ----------

  function check() {
    const form = el("form", "row");
    const input = el("input", "input");
    input.type = "text";
    input.id = "probe";
    input.value = probe.target;
    input.placeholder = "Домен, IP или ссылка";
    input.spellcheck = false;
    input.autocomplete = "off";
    input.setAttribute("aria-label", "Адрес для проверки");
    const btn = el("button", "btn", probe.busy ? "Проверяем…" : "Проверить");
    btn.type = "submit";
    btn.disabled = probe.busy;
    form.append(input, btn);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      probe = { target: input.value.trim(), result: null, error: "", busy: true };
      render();
      try { probe.result = verdictView(await svc("Explain", getSettings(), probe.target), getState()?.proxy?.current); }
      catch (err) { probe.error = (err && err.message) || String(err); }
      probe.busy = false;
      render();
    });

    const out = [subhead("Проверить адрес", () => go("overview")), form];
    if (isDirty()) out.push(el("div", "hint pad", "Проверка идёт по правилам, которые вы ещё не применили."));
    if (probe.error) out.push(el("div", "hint bad pad", probe.error));
    if (probe.result) {
      const r = probe.result;
      const box = el("div", "card stack verdict");
      const head = el("div", "row");
      head.append(el("span", "dest-dot big " + r.action), (() => {
        const t = el("div", "card-text");
        t.append(el("div", "card-title", r.title), el("div", "card-sub", r.sub));
        return t;
      })());
      box.append(head, el("div", "hint", r.why));
      for (const note of r.notes) box.append(el("div", "hint", note));
      out.push(box);
    }
    return out;
  }

  function render() {
    if (!getSettings()) return;
    const scroll = root.scrollTop;
    const build = { overview, categories, edit: editor, check }[view] || overview;
    const nodes = build();
    root.replaceChildren(...nodes);
    root.scrollTop = scroll;
  }

  return { render, show: (next) => go(next) };
}
