# vpn-client

VPN-клиент для Windows с раздельной маршрутизацией:

| Трафик | Куда |
|---|---|
| Корпоративный: `*.corp.example.com`, подсети и DNS-домены от сервера OpenVPN | OpenVPN |
| Зарубежный | VLESS (Reality / TLS) |
| Российские сайты, локальная сеть, всё остальное | напрямую |

Сетевую часть выполняет [sing-box](https://sing-box.sagernet.org/) 1.14+: TUN-интерфейс,
встроенный OpenVPN-клиент, VLESS и DNS. `vpnclient` собирает для него конфиг из
простого профиля и `.ovpn`, запускает и корректно останавливает. Отдельный
OpenVPN ставить не нужно.

```
profile.yaml + corp.ovpn ──► vpnclient ──► конфиг sing-box (через stdin) ──► sing-box
                                                                     ├─ TUN (весь трафик ПК)
                                                                     ├─ openvpn-client → корпоративная сеть
                                                                     ├─ vless → зарубежные сайты
                                                                     └─ direct → остальное
```

## Установка из релиза

1. Скачайте архив `vpnclient-vX.Y.Z-windows-amd64.zip` со страницы
   [Releases](https://github.com/maks-ard/vpn-client/releases/latest) и распакуйте его.
   В архиве лежат `vpnclient.exe`, `sing-box.exe`, `connect.cmd` и `profile.example.yaml`.
2. Переименуйте `profile.example.yaml` в `profile.yaml`, впишите ссылку `vless://…`
   и положите рядом свой `.ovpn`.
3. Запустите `connect.cmd`: он запросит права администратора и подключит VPN.
   Чтобы отключиться, закройте окно или нажмите Ctrl+C.

## Сборка из исходников

1. Соберите клиент (нужен Go 1.26+) и скачайте sing-box:
   ```powershell
   .\scripts\build.ps1
   ```
   В `dist\` появятся `vpnclient.exe`, `sing-box.exe` и `example.yaml`.
2. Скопируйте `dist\example.yaml` в `dist\profile.yaml`, впишите ссылку `vless://…`,
   положите рядом `corp.ovpn` и при необходимости логин и пароль OpenVPN.
3. Проверьте профиль:
   ```powershell
   .\dist\vpnclient.exe check
   ```
4. Подключитесь из консоли **от имени администратора**:
   ```powershell
   .\dist\vpnclient.exe run
   ```
   Ctrl+C отключает VPN, sing-box сам убирает TUN и маршруты.

Другие команды: `vpnclient config` выводит итоговый конфиг sing-box для отладки
(в нём есть ключи и пароли), `vpnclient version` показывает версию.

## Как разводится трафик

1. Домены из `corporate.domains` с поддоменами, подсети из `corporate.subnets`,
   а также маршруты и DNS-домены, которые прислал сервер OpenVPN, идут через OpenVPN.
   Корпоративные домены резолвятся DNS-серверами из OpenVPN.
2. Частные сети (LAN) и программы из `routing.direct_processes` идут напрямую.
3. Домены из `routing.proxy_domains` идут через VLESS, домены из `routing.direct_domains` напрямую.
4. Домены `.ru`, `.su`, `.рф`, списки `geosite-category-ru` и `geoip-ru` идут напрямую
   (это можно отключить через `routing.russia_direct: false`).
5. Всё остальное идёт через VLESS, его DNS ходит через DoH по VLESS.

`redirect-gateway` и `block-outside-dns` от сервера OpenVPN игнорируются, поэтому
весь трафик через корпоративную сеть не уходит. IPv6 по умолчанию блокируется,
чтобы не было утечек мимо TUN.

## Ограничения `.ovpn`

Поддерживается `dev tun` с сертификатами и ключами в PEM (inline или файлами), с
`tls-auth`, `tls-crypt` и `tls-crypt-v2`, а также с логином и паролем. Не
поддерживаются PKCS#12, сертификаты из хранилища Windows, блоки `<connection>`,
`dev tap` и подключение через HTTP/SOCKS-прокси. Неизвестные директивы выводятся
как предупреждения.

## Планы

- [x] Ядро: профиль, конвертер `.ovpn`, ссылки VLESS, генерация конфига, CLI
- [ ] Служба Windows и автозапуск
- [ ] GUI на Wails и иконка в трее: статус, переключатель, трафик через Clash API
- [ ] Импорт подписок и выбор сервера, kill switch
