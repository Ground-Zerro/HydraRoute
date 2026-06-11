# HydraRoute Neo

**HydraRoute Neo** — демон для раздельной маршрутизации трафика по доменам и CIDR на роутерах **Keenetic**.  
Перехватывает DNS-ответы, добавляет полученные IP в ipset и маркирует трафик для перенаправления через нужный туннель или интерфейс. Дополнительно — параллельный L7-канал: TLS SNI и HTTP Host (закрывает слепые зоны DoH/DoT, hardcoded-IP, легаси-HTTP; совместим с zapret2/nfqws2). Написан на C, единый статически скомпилированный бинарь без внешних зависимостей кроме libc и Linux API.

---

## Оглавление

- [Возможности](#возможности)
- [Системные требования](#системные-требования)
- [Установка и обновление](#установка-и-обновление)
- [Файлы конфигурации](#файлы-конфигурации)
- [Параметры hrneo.conf](#параметры-hrneoconf)
- [Работа с доменами (domain.conf)](#работа-с-доменами-domainconf)
- [Работа с CIDR (ip.list)](#работа-с-cidr-iplist)
- [L7-перехват (TLS SNI / HTTP Host)](#l7-перехват-tls-sni--http-host)
- [Политики доступа](#политики-доступа)
- [Веб-интерфейс (HRweb)](#веб-интерфейс-hrweb)
- [Управление](#управление)
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
- Перехват DNS-ответов LAN- и VPN-клиентов роутера (Ethernet, PPP, WireGuard, VPN-сервер, IPsec, туннели)
- Параллельный L7-канал (опц.): TLS SNI и HTTP Host через NFLOG с TCP-реассамблецией длинных ClientHello (Kyber/MLKEM)
- Корректная маршрутизация без переподключения (опц. ConntrackFlush)
- Управление через веб-интерфейс

---

## Системные требования

- Роутер Keenetic с прошивкой выше v4.3.6
- Установленная [Entware](https://help.keenetic.com/hc/ru/articles/360021214160)
- Добавлен системный компонент Keenetic `Xtables-addons для Netfilter`

---

## Установка и обновление

Выполните команду в терминале роутера:
```bash
opkg update && opkg install curl && curl -Ls "https://git.zerrolabs.org/Ground-Zerro/release/pages/keenetic/install-neo.sh" | sh
```

> Веб-интерфейс (HRweb) также будет установлен и доступен по ссылке `http://<IP роутера>:2000`  
> Службы запустятся автоматически

<details>
<summary>Установка вручную</summary>

1. Добавьте репозиторий:
```bash
curl -Ls "https://git.zerrolabs.org/Ground-Zerro/release/pages/keenetic/install-feed.sh" | sh
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

Всего **27 параметров** конфигурации, сгруппированных по назначению:

- **Основные:** `autoStart`, `watchlistPath`, `clearIPSet`
- **CIDR:** `CIDR`, `CIDRfile`
- **IPSet:** `IpsetEnableTimeout`, `IpsetTimeout`, `IpsetMaxElem`
- **Логирование:** `log`, `logfile`
- **DirectRoute:** `DirectRouteEnabled`, `InterfaceFwMarkStart`, `InterfaceTableStart`
- **Conntrack:** `ConntrackFlush`
- **Маршрутизация:** `GlobalRouting`, `PolicyOrder`
- **GeoIP / GeoSite:** `GeoIPFile`, `GeoSiteFile` (оба повторяемые)
- **L7-перехват:** `l7CaptureEnabled`, `l7NflogGroup`, `l7EnableTLS`, `l7EnableHTTP`, `l7WanInterface`, `l7ConnbytesMax`, `l7TcpReasmEnabled`, `l7TcpReasmMaxEntries`, `l7TcpReasmTtlSec`

> Полное описание каждого параметра, дефолтов, поведения и взаимодействия с роутером (RCI, PolicyOrder, ConntrackFlush и т.д.) — см. **[docs/HRNEO.CONF.md](docs/HRNEO.CONF.md)**.

Любой параметр доступен и как CLI-флаг (`--имя value`); приоритет: **CLI > конфиг-файл > встроенные дефолты**. Дефолтный `hrneo.conf` со всеми ключами генерируется командой `hrneo --genconfig /opt/etc/HydraRoute/`.

---

## Работа с доменами (domain.conf)

Формат строки:
```
домен1,домен2,geosite:tag/ПолитикаИлиИнтерфейс
```

- Домен — точное совпадение и все поддомены
- `geosite:TAG` — загрузить домены из GeoSite `.dat` файла для указанного тега
- Имя после `/` — если совпадает с именем системного интерфейса: `DirectRoute`, иначе: политика Keenetic
- Строки, начинающиеся с `#` или `##` — комментарии
- Длина строки не ограничена

Примеры:
```
## Через политику Keenetic
youtube.com,googlevideo.com/HydraRoute

## Через конкретный интерфейс
openai.com,chatgpt.com/nwg0

## GeoSite категория
geosite:google/HydraRoute

## GeoSite + обычные домены в одной строке
geosite:google,youtube.com,youtu.be/HydraRoute

## Несколько GeoSite категорий
geosite:google,geosite:netflix/HydraRoute
```

> GeoSite-домены поддерживают типы Domain (домен + поддомены) и Full (только точное имя)  
> Типы Plain (keyword) и Regex не поддерживаются  
> Записи из `domain.conf` имеют приоритет над GeoSite

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
geoip:ru
```

- `/ПолитикаИлиИнтерфейс` — активный блок
- `#/ПолитикаИлиИнтерфейс` — отключённый блок (содержимое игнорируется)
- `##` — комментарий
- `geoip:ru` — загрузить CIDR для страны из GeoIP-файлов (например `geoip:ru`, `geoip:us`)
- Пустая строка завершает текущий блок
- `/32` и `/128` добавляются как хосты, остальное — как подсети
- CIDR-записи добавляются как постоянные (без таймаута), даже при включённом `IpsetEnableTimeout`
- Длина строки не ограничена

Один блок для нескольких политик и отключение отдельных подблоков:
```
##Google CDN
/HydraRoute
10.203.14.12/28

##YouTube (временно отключено)
#/HydraRoute
172.22.48.77/26
```

> Если `geoip:TAG` содержит записей больше `IpsetMaxElem − 5000`, тег автоматически переносится в раздел `#/Too-big-geoip-tag`

---

## L7-перехват (TLS SNI / HTTP Host)

Параллельный DNS-каналу источник имён хостов. По умолчанию выключен (`l7CaptureEnabled=false`); включается `l7CaptureEnabled=true`. Закрывает слепые зоны DNS-only схемы:

- клиенты с DoH/DoT/DoQ (DNS зашифрован)
- hardcoded-IP с TLS SNI (без DNS-резолва)
- легаси-HTTP
- тёплый DNS-кэш устройства (TTL ещё не истёк)

L7 видит имя хоста уже после установления соединения (выпущенного через WAN до попадания IP в ipset). Поэтому при первом добавлении такого IP Neo сбрасывает триггернувшее соединение единичным TCP RST в сторону клиента — браузер мгновенно переустанавливает его новым соединением, которое с самого начала идёт по нужной политике, без обрыва в середине TLS-хендшейка.

**Известные ограничения:**
- **QUIC / HTTP-3 (UDP/443)** — не реализовано; значимо для Apple-устройств (Safari/iCloud/Push активно используют h3)
- **ECH (Encrypted ClientHello)** — нерешаемо без MITM
- **iCloud Private Relay** — by design зашифрованный туннель

Полный технический разбор — в [docs/HRNEO.CONF.md](docs/HRNEO.CONF.md) и [docs/CORE.md](docs/CORE.md).

---

## Политики доступа

- Создаются автоматически при запуске Neo или по `neo restart`
- Если политика удалена, но в `domain.conf` она есть — пересоздаётся
- Политика без активных доменов (нет, или все выклчюены) — не создается
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

Интерфейс разделён на пять разделов (боковое меню) и общую панель с показателями CPU/RAM роутера, версиями hrneo/hrweb и моделью устройства.

**Dashboard — маршрутизация:**
- Управление политиками Keenetic и DirectRoute-интерфейсами (создание, удаление, редактирование)
- Редактор доменов и CIDR для каждой цели
- Импорт списков: из репозиториев [Geo-Aggregator](https://github.com/Ground-Zerro/Geo-Aggregator), по тегам GeoIP/GeoSite, с [iplist.opencck.org](https://iplist.opencck.org/), а также из произвольной ссылки
- Валидация доменов и CIDR, обнаружение конфликтов между политиками
- Экспорт и импорт всей конфигурации (политики + домены + CIDR) в CSV

**Proxy:** три подраздела на вкладках:
- **XRay** — установка/запуск/остановка службы; конструктор интерфейсов из share-ссылок (`vless://`, `vmess://`, `trojan://`, `ss://`, `socks://`, `http://`) и URL подписок; редактор JSON-конфигов с подсветкой; при нескольких серверах автоматически создаётся балансировщик
- **Монитор** — фоновый мониторинг доступности через captive-check (HTTP 204) с настраиваемым интервалом, порогами отказа/восстановления, таймаутом и выбором интерфейсов; автоматический failover на резервный канал при недоступности основного

**HrNeo — управление демоном:**
- Запуск/остановка службы hrneo
- Управление GeoIP/GeoSite файлами: загрузка, автообновление по расписанию (с выбором часового пояса), переключение источника (GitHub Loyalsoldier или ZerroLabs RU)
- Раздел **«DANGER ZONE»** — редактирование всех 27 параметров `hrneo.conf` через формы с подсказками
- **Диагностика** — пошаговая проверка маршрутизации для указанного домена (политика, интерфейс, состояние ipset, правила iptables, доступность VPN)

**Info — справка:**
- Список полезных утилит сообщества (Domain Inspector, GEODAT EXPLORER, b4, web4core, HydraRoute Manager, Keenetic SSH, Flashkeen и др.)
- Раздел благодарностей донорам
- Отказ от ответственности

**Settings — глобальные настройки:**
- Отключение проверок доменов/DNS, виджет производительности, отображение всех xRay-конфигов
- Кастомные HTTP-заголовки (User-Agent и др.) для загрузки подписок и Geo-файлов
- Выбор источника Geo-файлов ([GitHub](https://github.com/Ground-Zerro/Geo-Aggregator) / [ZerroLabs RU](https://git.zerrolabs.org/Ground-Zerro/Geo-Aggregator))
- Узел проверки доступности (Google, Cloudflare, Apple и др., либо собственный URL)

</details>

Также доступны сторонние решения:
- [**awg-manager**](https://github.com/hoaxisr/awg-manager)
- [**web4static**](https://github.com/spatiumstas/web4static)

---

## Управление

```bash
neo start     # Запуск HydraRoute Neo
neo stop      # Остановка и очистка iptables/ip rule + NFLOG-правила L7
neo restart   # Перезапуск с пересозданием политик
neo status    # Проверка состояния службы
```

CLI hrneo (все параметры конфига доступны как `--flag value`):
```bash
hrneo --version              # вывести версию
hrneo --help                 # справка по флагам
hrneo --genconfig [path]     # сгенерировать дефолтный hrneo.conf
hrneo --config <path>        # указать альтернативный путь к hrneo.conf
```

Приоритет источников значений: **CLI флаги > конфиг-файл > встроенные дефолты**.

---

## Удаление

Полное: включая логи, конфиги, зависимые пакеты, откат всех изменений системы (рекомендуется):
```bash
curl -Ls "https://git.zerrolabs.org/Ground-Zerro/release/pages/keenetic/hr-uninstall.sh" | sh
```

> Будут удалены:  
> - пакеты: `hrneo`, `hrweb`, `ipset`, `iptables`, `jq`, `hydraroute`, `adguardhome-go`, `node`, `node-npm`, `xray`, `xray-core`  
> - папки: `/opt/etc/HydraRoute`, `/opt/etc/AdGuardHome`, `/opt/etc/xray/`

Стандартное:
```bash
opkg remove hrneo
```

---

## Срабатывания антивирусов и проверка подлинности

Релизные бинарники HRNeo иногда помечаются эвристикой антивирусов (на VirusTotal и т.п.) как угроза. Это **ложные срабатывания**: HRNeo — статически слинкованный stripped-ELF для MIPS/ARM, и по форме файла и набору системных вызовов (`AF_PACKET`, netlink, `iptables`/`conntrack`, `init_module`) технически неотличим от роутерного ПО, под которое заточены универсальные сигнатуры. В бинарниках нет C2, скрытой нагрузки, самораспространения, обфускации или упаковки.  

Чтобы можно было убедиться в подлинности файлов, каждый [GitHub Release](https://github.com/Ground-Zerro/HydraRoute/releases):

- содержит файл `SHA256SUMS` с фиксированными SHA-256 всех бинарников и `.ipk`-пакетов;
- каждый артефакт (включая `SHA256SUMS`) сопровождается откреплённой GPG-подписью `*.asc`;
- публичный ключ для проверки — `Neo/RELEASE_SIGNING_KEY.asc` в репозитории.

Проверка на ПК с установленным `gpg` (из каталога со скачанными файлами релиза):

```sh
gpg --import Neo/RELEASE_SIGNING_KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS   # подпись верна → "Good signature"
sha256sum -c SHA256SUMS                  # хеши файлов совпадают
```

Хеши фиксируются на релиз и не меняются — это снижает вес «редкий/новый образец» в эвристике и позволяет вендорам белым списком убрать конкретные детекты.

---

## Лицензия

HydraRoute Neo распространяется на условиях **GNU Affero General Public License v3.0 (AGPL-3.0-only)** — см. [LICENSE](LICENSE).

Программа предоставляется «как есть», без каких-либо гарантий. Автор не несёт ответственности за последствия использования.

**Поддержать проект:** [Boosty](https://boosty.to/ground_zerro)
