# AGENTS.md

Инструкции для AI-агентов (Claude Code, Codex, Cursor и др.), работающих с этим
репозиторием. Пользовательская документация лежит в [README.md](README.md).

## Проект

VPN-клиент для Windows на Go с раздельной маршрутизацией: корпоративный трафик
(`*.corp.example.com` и всё, что прислал сервер) идёт через OpenVPN, зарубежный
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
VPNCLIENT_SINGBOX=/path/to/sing-box go test ./internal/singbox/   # + проверка конфига настоящим sing-box
go run ./cmd/vpnclient config -p internal/singbox/testdata/profile.yaml   # посмотреть итоговый конфиг
```

Собрать sing-box для `VPNCLIENT_SINGBOX` (версия и теги как в CI):

```bash
GOTOOLCHAIN=auto GOBIN=$PWD/.bin go install \
  -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_clash_api,with_openvpn,badlinkname,tfogo_checklinkname0" \
  -ldflags "-checklinkname=0" github.com/sagernet/sing-box/cmd/sing-box@v1.14.3
```

Перед коммитом должны проходить: `gofmt`, `go vet` (linux и windows), `go test ./...`.

## Структура

```
cmd/vpnclient/       CLI: run | check | config | version
internal/profile/    профиль пользователя (YAML), значения по умолчанию, валидация
internal/ovpn/       парсер .ovpn → ovpn.Config (без зависимостей от sing-box)
internal/vless/      парсер ссылок vless://
internal/singbox/    сборка JSON-конфига sing-box из profile + vless + ovpn
internal/runner/     запуск и остановка sing-box; *_windows.go / *_other.go
profiles/example.yaml  документированный пример профиля
scripts/*.ps1        сборка под Windows и загрузка sing-box
internal/singboxbin/  sing-box.exe, встроенный в релизную сборку (тег embed_singbox)
winres/winres.json   манифест (requireAdministrator) и версия exe для go-winres
.github/workflows/   ci.yml (каждый push и PR), release.yml (теги v*)
```

Зависимости направлены строго вниз: `cmd` → `singbox` → `profile`/`ovpn`/`vless`;
`runner` ни от чего внутреннего не зависит.

## Правила для конфига sing-box

- Ориентируйся на формат **sing-box 1.14**. Не используй устаревшее и удалённое:
  legacy DNS-серверы (`address: "tls://..."`), `geoip`/`geosite` в route,
  поля sniff и domain_strategy в inbound, outbound-ы `dns`/`block`,
  `download_detour`. Список — в `docs/deprecated.md` исходников sing-box.
  Новые поля сверяй с документацией в модуле
  (`$(go env GOMODCACHE)/github.com/sagernet/sing-box@v1.14.3/docs/`), а не по памяти.
- Любое изменение генератора проверяй через `TestSingBoxCheck` с настоящим sing-box.
- Порядок правил маршрутизации важен: корпоративное → частные сети → процессы →
  `proxy_domains` → `direct_domains` → российские → `final`. Тесты в
  `internal/singbox/config_test.go` фиксируют этот порядок, держи их в актуальном состоянии.
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
  оставались на диске. `vpnclient config -o` пишет файл с правами `0600`.
- Не отключай `strict_route` в TUN: на Windows он защищает от DNS-утечек.

## Релизы

- Релиз собирает `.github/workflows/release.yml` при пуше тега `vX.Y.Z`
  (SemVer: пока `v0.x`, API и формат профиля могут меняться).
  В релиз попадает **один exe** на архитектуру (windows-amd64, windows-arm64)
  и его `.sha256`: официальный `sing-box.exe` встраивается через `go:embed`
  (тег `embed_singbox`), манифест с `requireAdministrator` — через go-winres.
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
