# HydraRoute Neo

**HydraRoute Neo** — демон для раздельной маршрутизации трафика по доменам и CIDR на роутерах **Keenetic**. Перехватывает DNS-ответы через NFLOG, добавляет IP-адреса в ipset и маркирует трафик в iptables для перенаправления через нужный туннель или интерфейс. Написан на Go, без CGO, единый бинарник.

---

## Оглавление

- [Возможности](#возможности)
- [Системные требования](#системные-требования)
- [Установка и обновление](#установка-и-обновление)
- [Файлы конфигурации](#файлы-конфигурации)
- [Параметры hrneo.conf](#параметры-hrneoconf)
- [Работа с доменами (domain.conf)](#работа-с-доменами-domainconf)
- [Работа с CIDR (ip.list)](#работа-с-cidr-iplist)
- [Политики доступа](#политики-доступа)
- [Веб-интерфейс (HRweb)](#веб-интерфейс-hrweb)
- [Управление](#управление)
- [IPv6](#ipv6)
- [Удаление](#удаление)
- [Лицензия](#лицензия)

---

## Возможности

- Не требует отключения системного DNS-сервера роутера
- Не встраивается в цепочку DNS, не использует сторонних компонентов
- Совместим с любой конфигурацией DNS на роутере: системный резолвер, DNS-маршрутизация Keenetic, AdGuard Home
- Маршрутизация через политики доступа Keenetic
- Прямая маршрутизация трафика на сетевые интерфейсы (DirectRoute)
- Поддержка статических CIDR-диапазонов с IPv4 и IPv6
- Работа с базами GeoIP и GeoSite в формате v2ray/xray `.dat`
- Корректная маршрутизация без переподключения
- Полная поддержка IPv6
- Управление через веб-интерфейс HRweb

---

## Системные требования

- Роутер Keenetic с прошивкой выше v4.3.6
- Установленная [Entware](https://help.keenetic.com/hc/ru/articles/360021214160)
- Добавлен систменый компонент Keenetic `Xtables-addons для Netfilter`

---

## Установка и обновление

Выполните команду в терминале роутера:
```bash
opkg update && opkg install curl && curl -Ls "https://ground-zerro.github.io/release/keenetic/install-neo.sh" | sh
```

> Веб-интерфейс (HRweb) также будет устанволен и доступен по ссылке `http://<IP роутера>:2000`  
> Службы запустятся автоматически

<details>
<summary>Установка вручную</summary>

1. Добавьте репозиторий:
```bash
curl -Ls "https://ground-zerro.github.io/release/keenetic/install-feed.sh" | sh
```
2. Установите Neo:
```bash
opkg install hrneo
```

</details>

Обновление:
```bash
opkg update && opkg upgrade
```

> Файлы `domain.conf` и `ip.list` сохраняются при обновлении (conffiles)

---

## Файлы конфигурации

| Файл | Назначение |
|------|------------|
| `/opt/etc/HydraRoute/hrneo.conf` | Основная конфигурация демона |
| `/opt/etc/HydraRoute/domain.conf` | Список доменов и политик/интерфейсов |
| `/opt/etc/HydraRoute/ip.list` | Статические CIDR-диапазоны |

---

## Параметры hrneo.conf

<details>
<summary>Все параметры с описанием</summary>

**Основные:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `autoStart` | `true` | `false` — немедленное завершение без изменения iptables/ipset |
| `watchlistPath` | `/opt/etc/HydraRoute/domain.conf` | Путь к файлу доменов |
| `clearIPSet` | `true` | Очищать ipset при запуске; `false` — сохранять накопленные IP |

**CIDR:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `CIDR` | `true` | Включить загрузку статических IP/подсетей из `CIDRfile` |
| `CIDRfile` | `/opt/etc/HydraRoute/ip.list` | Путь к файлу CIDR |

**IPSet:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `IpsetEnableTimeout` | `true` | Автоматическое удаление записей по таймауту |
| `IpsetTimeout` | `21600` | Таймаут в секундах (21600 = 6 часов, 86400 = 24 часа) |

> При повторном добавлении существующего IP таймаут не обновляется.

**Логирование:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `log` | `off` | Режим: `console` — stdout, `file` — файл, остальное — отключено |
| `logfile` | `/opt/var/log/LOGhrneo.log` | Путь к файлу логов (только при `log=file`) |

> Включать логирование без целей отладки не рекомендуется.

Уровни лога: `[DEBUG]` `[INFO]` `[MATCH]` `[PROCESSED]` `[FILTERED]` `[WARN]` `[ERROR]`

**DirectRoute (прямая маршрутизация на интерфейс):**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `DirectRouteEnabled` | `true` | Включить прямую маршрутизацию на сетевые интерфейсы |
| `InterfaceFwMarkStart` | `12289` | Начальный fwmark (0x3001) для интерфейсов |
| `InterfaceTableStart` | `301` | Начальный номер таблицы маршрутизации |

> Если в `domain.conf` цель совпадает с именем системного интерфейса — настраивается `ip rule + ip route`, иначе — политика Keenetic.
> Если интерфейс DOWN при старте — создаётся blackhole-маршрут, который обновляется по SIGUSR1.

**Conntrack:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `ConntrackFlush` | `true` | Сбрасывать conntrack-записи при первом добавлении IP в ipset |

> Обеспечивает корректную маршрутизацию без разрыва уже установленных соединений вручную.

**Глобальная маршрутизация:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `GlobalRouting` | `false` | `false` — уважать политики роутера (NoVPN, Policy0 и т.д.); `true` — перезаписывать все политики |

**Порядок политик:**

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `PolicyOrder` | `HydraRoute` | Порядок добавления правил iptables через запятую; определяет приоритет при совпадении IP в нескольких ipset |

**GeoIP:**

```
GeoIPFile=/opt/etc/HydraRoute/geofile/geoip.dat
GeoIPFile=/opt/etc/HydraRoute/geofile/geoip_RU.dat
```
Путь к базе GeoIP в формате v2ray/xray `.dat`. Параметр повторяем. Используется совместно с директивой `geoip:CC` в `ip.list`.

**GeoSite:**

```
GeoSiteFile=/opt/etc/HydraRoute/geofile/geosite.dat
GeoSiteFile=/opt/etc/HydraRoute/geofile/geosite_RU.dat
```
Путь к базе GeoSite в формате v2ray/xray `.dat`. Параметр повторяем. Используется совместно с директивой `geosite:TAG` в `domain.conf`.

**Пример конфигурации по умолчанию:**
```
autoStart=true
watchlistPath=/opt/etc/HydraRoute/domain.conf
clearIPSet=true
IpsetEnableTimeout=true
IpsetTimeout=21600
CIDR=true
CIDRfile=/opt/etc/HydraRoute/ip.list
DirectRouteEnabled=true
InterfaceFwMarkStart=12289
InterfaceTableStart=301
GlobalRouting=false
ConntrackFlush=true
log=off
logfile=/opt/var/log/LOGhrneo.log
PolicyOrder=HydraRoute
```

</details>

---

## Работа с доменами (domain.conf)

Формат строки:
```
домен1,домен2,geosite:TAG/ПолитикаИлиИнтерфейс
```

- Домен — точное совпадение и все поддомены
- `geosite:TAG` — загрузить домены из GeoSite `.dat` файла для указанного тега
- Имя после `/` — если совпадает с именем системного интерфейса: DirectRoute, иначе: политика Keenetic
- Строки, начинающиеся с `#` или `##` — комментарии

Примеры:
```
## Через политику Keenetic
youtube.com,googlevideo.com/HydraRoute

## Через конкретный интерфейс
openai.com,chatgpt.com/nwg0

## GeoSite категория
geosite:GOOGLE/HydraRoute

## GeoSite + обычные домены в одной строке
geosite:GOOGLE,youtube.com,youtu.be/HydraRoute

## Несколько GeoSite категорий
geosite:GOOGLE,geosite:NETFLIX/HydraRoute
```

> GeoSite-домены поддерживают типы Domain (домен + поддомены) и Full (только точное имя)  
> Типы Plain (keyword) и Regex не поддерживаются  
> Записи из `domain.conf` имеют приоритет над GeoSite

Популярные теги GeoSite: `GOOGLE`, `NETFLIX`, `TELEGRAM`, `RU`, `CN`.

---

## Работа с CIDR (ip.list)

Формат:
```
##Описание блока
/ПолитикаИлиИнтерфейс
10.0.0.0/8
192.168.1.1/32
2606:4700::/32

##Отключённый блок
#/ПолитикаИлиИнтерфейс
45.67.123.0/24

##GeoIP директива
/HydraRoute
geoip:RU
```

- `/ПолитикаИлиИнтерфейс` — активный блок
- `#/ПолитикаИлиИнтерфейс` — отключённый блок (содержимое игнорируется)
- `##` — комментарий
- `geoip:CC` — загрузить CIDR для страны из GeoIP-файлов (например `geoip:RU`, `geoip:CN`)
- Пустая строка завершает текущий блок
- `/32` и `/128` добавляются как хосты, остальное — как подсети
- CIDR-записи добавляются как постоянные (без таймаута), даже при включённом `IpsetEnableTimeout`

Один блок для нескольких политик и отключение отдельных подблоков:
```
##Google CDN
/HydraRoute
10.203.14.12/28

##YouTube (временно отключено)
#/HydraRoute
172.22.48.77/26
```

> Избегайте перекрывающихся подсетей в разных политиках

---

## Политики доступа

- Создаются автоматически при запуске Neo или по `neo restart`
- Если политика удалена, но в `domain.conf` она есть — пересоздаётся
- При остановке Neo (`neo stop`) трафик идёт напрямую без туннелей

> Приоритет маршрутизации задаётся в интерфейсе Keenetic: **Приоритеты подключений → Политики доступа**  
> В одной политике можно указать несколько VPN-подключений для [многопутевой маршрутизации](https://help.keenetic.com/hc/ru/articles/7490633500572)

---

## Веб-интерфейс (HRweb)

Отдельный компонент для визуального управления HydraRoute Neo без работы в терминале.

Установка:
```bash
opkg install hrweb
```

> После запуска интерфейс доступен по адресу: `http://<IP роутера>:2000`  
> Авторизация — через логин и пароль роутера Keenetic

<details>
<summary>Возможности HRweb</summary>

**Dashboard — управление маршрутизацией:**
- Управление политиками маршрутизации (обычные через Keenetic и интерфейсные DirectRoute)
- Добавление и редактирование доменов и CIDR для каждой политики
- Загрузка доменных списков из GitHub репозиториев и по прямым ссылкам
- Интеграция с [iplist.opencck.org](https://iplist.opencck.org/)
- Валидация доменов и CIDR, обнаружение конфликтов между политиками

**Proxy (xRay) — управление прокси:**
- Установка xRay
- Запуск и остановка службы xRay
- Создание прокси-интерфейсов через Builder из share-ссылок (`vless://`, `vmess://`, `trojan://`, `ss://`) и URL подписок
- Редактирование JSON конфигурации с подсветкой синтаксиса (CodeMirror)
- Удаление пользовательских интерфейсов
- Отображение статуса всех xRay-интерфейсов

**DANGER ZONE (HrNeo) — настройка демона:**
- Управление службой HrNeo (запуск/остановка)
- Редактирование всех параметров `hrneo.conf` через UI
- Управление GeoIP/GeoSite файлами: скачивание, автоматическое обновление по расписанию
- Настройка логирования

**Автообновление GeoIP/GeoSite:**
В разделе настроек HRweb можно настроить автоматическое скачивание и обновление баз GeoIP и GeoSite по расписанию. После загрузки hrneo перезапускается автоматически.
Поддерживаемые базы:
- `geoip.dat` / `geosite.dat` — [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)
- `geoip_RU.dat` / `geosite_RU.dat` — [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat)

</details>

Также доступно стороннее решение: [**web4static**](https://github.com/spatiumstas/web4static)

---

## Управление

```bash
neo start     # Запуск HydraRoute Neo
neo stop      # Остановка и очистка iptables/ip rule
neo restart   # Перезапуск с пересозданием политик
neo status    # Проверка состояния службы
```

---

## IPv6

Для работы IPv6 через VPN необходимо одновременное выполнение условий:
- IPv6 у основного провайдера
- IPv6 у VPN-сервера
- IPv6 у VPN-пира (WireGuard, OpenVPN и т.д.)
- Настроенная IPv6-маршрутизация на VPS

> Если IPv6 не используется — отключите его в настройках подключения провайдера и VPN

---

## Удаление

Полное: включая логи, конфиги, зависимые пакеты, откат всех изменений системы (рекомендуется):
```bash
curl -Ls "https://ground-zerro.github.io/release/keenetic/hr-uninstall.sh" | sh
```

> Будут удалены:  
> - пакеты: `hrneo`, `hrweb`, `ipset`, `iptables`, `jq`, `hydraroute`, `adguardhome-go`, `node`, `node-npm`, `xray`, `xray-core`  
> - папки: `/opt/etc/HydraRoute`, `/opt/etc/AdGuardHome`, `/opt/etc/xray/`

Стандартное:
```bash
opkg remove hrneo
```

---

## Лицензия

HydraRoute Neo распространяется бесплатно, «как есть». Автор не несёт ответственности за последствия использования.

**Поддержать проект:** [Boosty](https://boosty.to/ground_zerro)
