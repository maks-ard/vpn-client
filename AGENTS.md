# AGENTS.md

Инструкции для AI-агентов (Claude Code, Codex, Cursor и др.), работающих с этим
репозиторием. Пользовательская документация лежит в [README.md](README.md).

## Проект

VPN-клиент для Windows на Go с раздельной маршрутизацией: корпоративный трафик
(домены из настроек и всё, что прислал сервер) идёт через OpenVPN, зарубежный
через VLESS, остальное напрямую. Сетевую часть выполняет внешний процесс
**sing-box ≥ 1.14** (TUN, встроенный `openvpn-client`, VLESS, DNS). Наш код
только собирает его конфиг и управляет процессом. Своя сетевая логика (пакеты,
маршруты, WinAPI для сети) не пишется без явного решения владельца.

Целевая платформа — только Windows (amd64). Разработка и CI идут на Linux, поэтому
код должен собираться и тестироваться на обеих ОС.

## Команды

```bash
go build ./...                       # сборка
GOOS=windows go build ./...          # проверка, что Windows-сборка не сломана
go vet ./... && GOOS=windows go vet ./...
gofmt -l .                           # должно быть пусто
go test ./...                        # unit-тесты
VPNCLIENT_SINGBOX=/path/to/sing-box go test ./...   # + проверка конфига и полный цикл подключения с настоящим sing-box
go run ./cmd/vpnctl config -p internal/singbox/testdata/profile.yaml   # посмотреть итоговый конфиг
```

Собрать sing-box для `VPNCLIENT_SINGBOX` (версия и теги как в CI):

```bash
GOTOOLCHAIN=auto GOBIN=$PWD/.bin go install \
  -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_clash_api,with_openvpn,badlinkname,tfogo_checklinkname0" \
  -ldflags "-checklinkname=0" github.com/sagernet/sing-box/cmd/sing-box@v1.14.4
```

Перед коммитом должны проходить: `gofmt`, `go vet` (linux и windows), `go test ./...`.

## Структура

```
cmd/vpnclient/       один exe в нескольких ролях (только windows): окно и трей (Wails v3,
                     обычные права), --service (служба), --install/--uninstall/--restart-service
  frontend/          HTML/CSS/JS без сборщика; Go вызывается через /wails/runtime.js
  icons/             иконка приложения и 4 состояния иконки в трее (PNG)
cmd/vpnctl/          консольная утилита разработчика: run | check | config | version
internal/app/        логика без GUI: настройки, Manager (подключение, статус через
                     Clash API, журнал); работает внутри службы
internal/ipc/        HTTP поверх named pipe \\.\pipe\vpn-client: сервер в службе, клиент в окне
internal/winsvc/     служба Windows: запуск, установка в Program Files, ACL, UAC, перезапуск
internal/update/     автообновление из GitHub Releases с проверкой SHA-256
internal/profile/    профиль (YAML для vpnctl; GUI собирает его из настроек)
internal/subscription/  подписки: загрузка, base64, subscription-userinfo, кэш
internal/ovpn/       парсер .ovpn → ovpn.Config (без зависимостей от sing-box)
internal/vless/      парсер ссылок vless://
internal/singbox/    сборка JSON-конфига sing-box
internal/runner/     запуск/остановка sing-box, распаковка встроенного; *_windows.go / *_other.go
internal/killswitch/ kill switch: фильтры WFP (fwpuclnt.dll) в динамической сессии службы
internal/corproute/  маршруты Windows (iphlpapi.dll) через адаптер OpenVPN при «Адрес компании в Windows»
internal/singboxbin/ sing-box.exe, встроенный в релизную сборку (тег embed_singbox)
winres/winres.json   иконка, манифест (asInvoker: окно без прав) и версия exe для go-winres
profiles/example.yaml  пример профиля для vpnctl
.github/workflows/   ci.yml (каждый push и PR), release.yml (теги v*)
```

Архитектура: окно (без прав) ⇄ ipc ⇄ служба (SYSTEM) → app.Manager → sing-box.
Окно не читает файлы службы напрямую — всё через API. Исключение — журнал службы в
`%ProgramData%\vpn-client\logs` (читается всеми, ссылка на подписку в нём скрыта):
его окно открывает напрямую, когда служба не отвечает.

Зависимости направлены строго вниз: `cmd` → `winsvc`/`ipc` → `app` → `singbox` →
`profile`/`subscription`/`ovpn`/`vless`; `runner`, `killswitch` и `corproute` ни от чего внутреннего не зависят.
Wails импортирует только `cmd/vpnclient`: `internal/app` тестируется без GUI.

## GUI

- Фронтенд — обычные HTML/CSS/JS в `cmd/vpnclient/frontend`, без npm и сборщика.
  Методы Go вызываются как `Call.ByName("main.Service.<Метод>")`, состояние приходит
  событием `state`. Новый метод — экспортируемый метод `Service` в `service.go`.
- Дизайн согласован с владельцем (тёмная тема, окно 400×680, «Журнал» только в трее);
  заметные изменения внешнего вида сначала согласуй.
- Проверка вёрстки: открой `frontend/index.html` в Chromium (Playwright) с подменой
  `/wails/runtime.js` на мок и сними скриншоты состояний.
- Wails v3 пока в beta: версия зафиксирована в `go.mod`, обновляй осознанно.
- `cmd/vpnclient` собирается только под windows (`//go:build windows`), под Linux
  для него нужны GTK/WebKit — не добавляй их в CI.

## Правила для конфига sing-box

- Ориентируйся на формат **sing-box 1.14**. Не используй устаревшее и удалённое:
  legacy DNS-серверы (`address: "tls://..."`), `geoip`/`geosite` в route,
  поля sniff и domain_strategy в inbound, outbound-ы `dns`/`block`,
  `download_detour`. Список — в `docs/deprecated.md` исходников sing-box.
  Новые поля сверяй с документацией в модуле
  (`$(go env GOMODCACHE)/github.com/sagernet/sing-box@v1.14.4/docs/`), а не по памяти.
- Любое изменение генератора проверяй через `TestSingBoxCheck` с настоящим sing-box.
- Порядок правил маршрутизации важен: корпоративное → категории с направлением
  «OpenVPN» → частные сети → процессы → `proxy_domains` → `direct_domains` →
  остальные категории (в порядке списка) → российские → `final`. Тесты в
  `internal/singbox/config_test.go` и `categories_test.go` фиксируют этот порядок,
  держи их в актуальном состоянии.
- Категории (`routing.categories`, в GUI «Правила») — готовые из каталога
  `singbox.Presets()` (наборы sing-geosite, имена сверяй запросом к
  `raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/`) и свои. Направление
  `auto` не добавляет в конфиг ничего. Категория, которой некуда направлять трафик
  (нет OpenVPN или VLESS), пропускается с замечанием, а не ломает подключение.
- Недоступный remote rule-set роняет sing-box при старте (`FATAL initialize rule-set`),
  и VPN не поднимается вовсе. Поэтому приложение скачивает наборы категорий заранее,
  проверяет их самим sing-box (`rule-set match`) и передаёт в `Input.LocalSets`; набор,
  который получить не удалось, пропускается с предупреждением. Из приложения не клади
  в конфиг remote-ссылки на наборы категорий. Для `vpnctl` и тестов (`LocalSets == nil`)
  остаются remote.
- Конфиг без категорий не должен меняться ни на байт: это держат
  `TestGoldenLegacyRouting` (эталоны в `internal/singbox/testdata/golden`) и
  `TestLegacySettingsKeepRouting`. Эталоны обновляй (`UPDATE_GOLDEN=1`) только
  если поведение меняется осознанно, и скажи об этом в коммите.
- Без VLESS в конфиге не должно оставаться ссылок на тег `proxy`; без OpenVPN — на `corp`.
- Скачивание rule-set'ов не должно зависеть от VLESS, иначе при недоступном VLESS
  не поднимется и корпоративный доступ.
- Сервер OpenVPN не должен забирать весь трафик: `redirect-gateway` и
  `block-outside-dns` всегда игнорируются через `forcedPullFilters`.

## Стиль кода

- Обычный идиоматичный Go: `gofmt`, ошибки возвращаются с контекстом
  (`fmt.Errorf("openvpn: %w", err)`), без `panic` в рабочем коде.
- **Сообщения пользователю, ошибки и комментарии пишутся по-русски**,
  идентификаторы — по-английски. Комментарии объясняют «почему», а не «что».
- Платформенный код выносится в файлы `*_windows.go` / `*_other.go` с одинаковыми
  сигнатурами, без `runtime.GOOS` в логике там, где можно обойтись build-тегами.
- Новые внешние зависимости — только при явной необходимости. sing-box
  **не импортируется как библиотека** (тяжёлый граф зависимостей, GPL): только
  внешний процесс и собственные лёгкие структуры или `map[string]any`.
- Профиль парсится с `KnownFields(true)`: при новом поле обнови
  `profiles/example.yaml` с комментарием и README, если поле видно пользователю.

## Тесты

- Табличные тесты на стандартном `testing`, без сторонних фреймворков.
- Парсеры (`ovpn`, `vless`, `profile`) тестируются и на корректных входах, и на ошибках.
- Тестовые ключи и сертификаты в `internal/singbox/testdata/` сгенерированы только
  для тестов. Никогда не клади туда настоящие корпоративные данные.

## Безопасность

- **Никогда не коммить** реальные `.ovpn`, ключи, пароли, UUID и ссылки `vless://`,
  `profile.yaml`, корпоративные адреса и подсети. Они перечислены в `.gitignore`.
  Перед коммитом проверяй `git status` и diff.
- Конфиг передаётся в sing-box через stdin (`-c stdin`), чтобы секреты не
  оставались на диске. `vpnctl config -o` пишет файл с правами `0600`.
- Не отключай `strict_route` в TUN: на Windows он защищает от DNS-утечек.
- Kill switch (`internal/killswitch`, решение владельца) — единственная своя сетевая
  логика. Сессия WFP только динамическая: при падении службы Windows снимает фильтры,
  постоянные фильтры могут оставить машину без сети. Трафик через VPN разрешается по
  адресу TUN (`singbox.TunAddress4/6`), сменишь адрес — он сменится и здесь. Соединения
  с app ID `System` разрешены намеренно: антивирусы с проверкой трафика пересоздают в ядре соединения sing-box.
  Настоящие фильтры проверяет `TestEnable` (от администратора,
  `VPNCLIENT_KILLSWITCH_TEST=1`; на пару секунд отключает сеть у всей машины).
- Маршруты через адаптер OpenVPN (`internal/corproute`, решение владельца) — вторая
  своя сетевая логика. Включается только настройкой «Адрес компании в Windows»
  (`openvpn.system_interface`, endpoint с `system: true`). Маршруты ставятся только через
  этот адаптер и пропадают вместе с ним, когда sing-box завершается. Маршрут по умолчанию
  через адаптер с метрикой 9999 обязателен: sing-box открывает корпоративные соединения
  сокетом, привязанным к адаптеру, и без маршрута через него они не открываются (проверено
  на Linux). Общий TUN держит свой маршрут по умолчанию с метрикой 0, поэтому программы
  идут через TUN. Маршруты к отдельным адресам ставятся только к частным IPv4.

## Релизы

- Релиз собирает `.github/workflows/release.yml` при пуше тега `vX.Y.Z` или при
  ручном запуске (workflow_dispatch с полем `version`: тег создаётся самим релизом —
  так делай из облачных сессий, где пуш тегов запрещён)
  (SemVer: пока `v0.x`, API и формат профиля могут меняться).
  В релиз попадает **один exe** на архитектуру (windows-amd64, windows-arm64)
  и его `.sha256`: официальный `sing-box.exe` встраивается через `go:embed`
  (тег `embed_singbox`; плюс тег `production`, без него Wails собирается в отладочном режиме), иконка и манифест — через go-winres.
- Автообновление: служба раз в 6 часов смотрит `releases/latest`, качает
  `vpnclient-<тег>-windows-<arch>.exe` и `.sha256`, переименовывает текущий exe в
  `.old` и ставит новый, затем перезапускается через `--restart-service`.
  Если в скачанном exe тот же sing-box (`sameSingBox`: байты встроенного sing-box
  ищутся в файле, запускать его не нужно), обновление ставится сразу и при
  включённом VPN; иначе ждёт простоя или кнопки. При установке с включённым VPN
  служба не останавливает sing-box, а передаёт его новой версии (`Manager.HandOff` → `data/handoff.json` →
  `Manager.Adopt`): sing-box живёт в именованном Job Object, который
  `--restart-service --hold-job` держит открытым на время перезапуска. Если новая
  служба не поднялась, job закрывается и Windows завершает sing-box. Журнал
  подхваченного процесса читается из Clash API `/logs`, stdout остаётся у старой службы.
  **Не меняй имена файлов в release.yml** — на них завязаны уже установленные копии.
  Сборки с версией не вида `vX.Y.Z` (например, `dev`) не обновляются.
- Встроенный sing-box распаковывается в `data/` и держится открытым без права
  записи (`runner.Install`), пока работает: программа запущена от администратора,
  и подменить исполняемый файл между проверкой хэша и запуском нельзя.
- Версия sing-box для релизов задаётся в `SING_BOX_VERSION` в `release.yml`.
  При её изменении обнови версию в `ci.yml`, `scripts/fetch-singbox.ps1` и в этом файле.
- Версия приложения подставляется через `-X main.version=<тег>`, руками её не правь.
- Тег ставь только на коммит, у которого прошёл CI.

## Git

- Сообщения коммитов на русском, в повелительном наклонении, короткий заголовок
  до ~72 символов и тело с объяснением «почему».
- Один логический шаг — один коммит. Не смешивай рефакторинг и изменение поведения.
- В PR опиши, что изменилось в маршрутизации и как это проверено
  (`go test`, `sing-box check`, ручная проверка на Windows).
