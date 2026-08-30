# HRNeo — техническая документация кодовой базы

Исходный код HRNeo (HydraRoute Neo) v3.18.3-1: архитектура, модули, потоки данных, оптимизации.

---

## 1. Общая архитектура и принцип работы

HRNeo — демон для policy routing на роутерах Keenetic (Entware). Чистый C (без CGO, без внешних библиотек кроме libc и Linux API), единый статически скомпилированный бинарник.

### Два независимых источника имён хостов

- **DNS-канал** (всегда): перехват DNS-ответов dnsmasq через AF_PACKET SOCK_DGRAM + L3-BPF. Работает на интерфейсах любого типа — Ethernet, PPP, ARPHRD_NONE (WireGuard, VPN-сервер, IPsec, туннели). Ловит DNS и LAN-, и VPN-клиентов.
- **L7-канал** (опционально, `l7CaptureEnabled`): перехват TLS SNI / HTTP Host / QUIC Initial SNI исходящих соединений через NFLOG (пассивное копирование пакета, нетерминирующая цель). Фаза 2 — реассамблеция длинных ClientHello: TCP (по seq) и QUIC CRYPTO-фрагментов многодатаграммного Initial (MLKEM/Kyber), обе поверх общего пула `tcp_reasm`. QUIC — CRYPTO-walker с дешифровкой Initial-пакета. Подробно — раздел [18](#18-l7-перехват-tls-sni--http-host--tcp-реассамблеция).

### Принцип работы (пошагово)

1. Читается конфигурация из `/opt/etc/HydraRoute/hrneo.conf` (29 параметров; CLI-флаги поверх конфига; недостающие — встроенные дефолты).

2. Если `DirectRouteEnabled=true` — сканируется `/sys/class/net/`, строится карта системных интерфейсов (`drm_scan_interfaces`): для каждого имени читается `/sys/class/net/<name>/operstate` (`up`/`down`/`unknown`). Карта нужна, чтобы при разборе watchlist различать «политика Keenetic» и «сетевой интерфейс для DirectRoute».

3. Парсится watchlist (`domain.conf`). Каждая строка имеет формат `домен1,домен2,geosite:TAG/Цель`. Цель классифицируется через `drm_classify_target` по карте интерфейсов из шага 2:
   - имя совпало с интерфейсом → цель является интерфейсом (DirectRoute, маршрутизация будет через `ip rule + ip route`)
   - не совпало → цель является политикой Keenetic (маршрутизация будет через политику роутера с её mark)

   Результат: разделённые массивы `policy_names[]` и `iface_names[]`. Лог: `[INFO] domain.conf: %d policies, %d interfaces`.

4. Опционально (`CIDR=true`): из `CIDRfile` (`ip.list`) извлекаются уникальные заголовки `/Name` через `parse_cidr_policy_headers`. Каждое имя классифицируется через `drm_classify_target`: интерфейсы дописываются в `iface_names[]`, остальные — в список политик. Лог на каждое новое имя: `[INFO] CIDR: added policy 'X'`.

5. Опционально (есть `GeoSiteFile`): `parse_geosite_rules` собирает `geosite:TAG/Цель` из watchlist'а; цели раскладываются так же — интерфейсы в `iface_names[]`, политики в `policy_names[]`. Лог: `[INFO] GeoSite: added policy 'X'`.

   После шагов 4-5 для каждого имени из `iface_names[]` выделяются `fwmark`/`table_id` и регистрируется маршрут (`drm_register_route`). Регистрация идёт именно здесь, а не сразу после watchlist'а: цель-интерфейс может быть объявлена только в `ip.list` или в `geosite:`-правиле, и без этого она не получала бы ни ipset (в т.ч. `FLUSH` на старте), ни `CONNMARK`-правило, ни `ip rule`.

6. Применяется `PolicyOrder` через `sort_policies` (см. раздел [5](#5-матчинг-доменов-srcwatchlistc)). Сортировка делается дважды: для одних только политик (для шага 7) и для объединённого массива policy + iface (для шага 9). Итог печатается:

   ```
   [INFO] Target order (N):
     [0] HydraRoute (policy)
     [1] nwg0 (interface, fwmark=0x3001)
     ...
   ```

7. **Создание/проверка политик Keenetic через RCI** (`rci_create_policies`): hrneo формирует `POST /rci/ HTTP/1.0` с JSON-массивом `[{"parse":"ip policy <name1>"}, ..., {"system":{"configuration":{"save":true}}}]` и отправляет на `127.0.0.1:79` — создание политик и сохранение startup-config одним запросом. Команда `parse` эквивалентна вводу `ip policy <name>` в CLI Keenetic — существующие политики не трогает, отсутствующие создаются пустыми (без VPN-интерфейсов; их администратор присвоит через веб-интерфейс роутера Keenetic). Интерфейсы из `iface_names[]` в RCI не отправляются — для них политики Keenetic не нужны. Лог: `[INFO] Policy creation commands executed`. Подробнее — раздел [13](#13-rci-remote-configuration-interface-keenetic-srcrcic).

8. Создаются `ipset`-множества `hash:net` (IPv4 и IPv6 отдельно) для каждой цели (политика или интерфейс): по два сета на target — `<name>` (IPv4) и `<name>v6` (IPv6). Через netlink с `NLM_F_CREATE|NLM_F_EXCL`; существующие сеты не пересоздаются. Таймаут один на все сеты — поле `default_timeout` менеджера ipset (0 = без таймаута). При `clearIPSet=true` — `FLUSH` каждого сета.

9. Опционально (`CIDR=true`): загрузка статических CIDR-блоков в `ipset` (`add_cidr_to_ipsets`). Двухфазная обработка: фаза 1 — пресканирование `geoip:TAG` и автомиграция oversized тегов в disabled-секцию; фаза 2 — собственно `ipset_add_batch` для активных блоков.

10. Опционально (есть `GeoSiteFile`): `build_geosite_domain_map` загружает домены типов `Domain`/`Full` из `.dat`-файлов в хеш-таблицу с приоритетом у `domain.conf` (`ht_insert` НЕ перезаписывает существующие).

11. Если `DirectRoute=true` — `drm_setup_all_routes`:

    ```
    ip -4|-6 rule  add     priority N fwmark 0x<mark> table <T>
    ip -4|-6 route replace default via <gw> dev <iface> table <T>   # или blackhole
    ```

    `fwmark` и `table_id` уникальные, выделяются последовательно от `InterfaceFwMarkStart` (12289) и `InterfaceTableStart` (301).

12. **Извлечение `markID` политик через RCI** + создание `CONNMARK`-правил `iptables` (`apply_unified_connmark_rules`):
    - Для каждой цели-политики точечный `GET /rci/show/ip/policy/<Name>/mark` возвращает голое значение `"ffffaaa"` (~10 байт; HTTP 404 — политики нет). Полное дерево политик со всеми маршрутами не выкачивается, JSON-парсер не нужен — из ответа снимаются кавычки и префикс `0x`. Лог при `log=console/file`: `[DEBUG] RCI policy: HydraRoute mark=0xffffaaa`
    - Ретрая внутри RCI-клиента нет: и сетевая ошибка, и «политика создана, но `markID` ещё не назначен» дают `-1` из `apply_unified_connmark_rules`, а повтор обеспечивает коммитер (`commit_run`, фиксированные `NF_COMMIT_INTERVAL_MS` = 3 с, без роста интервала, бесконечно). Один механизм ожидания вместо трёх вложенных, и он не блокирует epoll-цикл
    - Для целей-интерфейсов `markID` не запрашивается — используется назначенный `fwmark`
    - Для каждой цели в порядке `g_all_sorted[]` формируется пара `CONNMARK`-правил в `mangle/PREROUTING`, через `iptables-restore --noflush` (один вызов на весь батч). Если у политики `mark` пустой — `LOG_WARN "Policy %s has no mark ID yet"`, цель пропускается в этом батче и выставляется `incomplete=1`: остальные цели применяются, но функция возвращает `-1` (`ipset` продолжит заполняться, но трафик этой цели не маркируется до следующего коммита)

13. Инициализируется `AF_PACKET` захват DNS-ответов: два `SOCK_DGRAM/ETH_P_ALL` сокета с L3-BPF (`fd4` для IPv4, `fd6` для IPv6).

14. Опционально (`l7CaptureEnabled=true`): резолв WAN (config или `/proc/net/route`), `init_module(nfnetlink_log+xt_NFLOG)` (при неудаче — L7 отключается, DNS-only), `init_module(xt_connbytes)`, `nflog_capture_init`, `NFLOG`-правила `iptables`/`ip6tables` в `mangle/FORWARD`+`OUTPUT` для TCP 443/80; при `l7TcpReasmEnabled` — `tcp_reasm_init` + `timerfd` GC (1с).

15. Основной epoll-цикл перехватывает DNS-ответы (`AF_PACKET`) и L7-пакеты (`NFLOG`), добавляет IP в `ipset` через netlink. Для L7-канала при **первом** добавлении IP (и при `ConntrackFlush=true`) триггернувшее соединение разрывается точечным удалением его conntrack-записи по полному 5-tuple (`conntrack_delete_conn`) — следующий пакет переоценивает `CONNMARK`-правила, а смена src/NAT через политику вынуждает легитимный реконнект по выбранному маршруту. Полный conntrack-DUMP (шаг 16) из L7-канала не выполняется — L7 использует точечный DELETE без сканирования таблицы.

16. Если `ConntrackFlush=true` И IP добавлен в `ipset` впервые (`NLM_F_EXCL` вернул `err==0`, а не `IPSET_ERR_EXIST`), IP попадает в pending-буфер `conntrack_flush_request` — conntrack-DUMP выполняется **асинхронно**: неблокирующий сокет `m->fd` зарегистрирован в том же epoll, чанки таблицы читаются между DNS-пакетами, DELETE по совпадению dst-IP уходит fire-and-forget. DNS-события никогда не ждут сканирования таблицы (при burst-резолвах ipset add всех доменов завершается до/независимо от DUMP'а), один DUMP обслуживает все накопленные IP. Реальное удаление происходит только при наличии активной `conntrack`-записи к IP; если соединения ещё нет — DUMP проходит вхолостую.

17. Обрабатываются сигналы:
    - `SIGUSR1` — обновление состояния интерфейсов + пересоздание `CONNMARK`-правил (включая повторный `GET /rci/show/ip/policy/` для возможно изменившихся `markID`) + реинсталл L7-правил. Вся таблица `mangle` пишется одной командой `iptables-restore --noflush` на семью, идемпотентность — по единственному дампу `-t mangle -S`, без `iptables -C`. При неактивном цикле коммита запись выполняется **немедленно**, подтверждающая — через `NF_COMMIT_INTERVAL_MS` = 3 с; пока цикл активен, сигналы игнорируются целиком (`timerfd`)
    - `SIGINT`/`SIGTERM` — штатная остановка: снятие L7 `NFLOG`-правил, удаление `CONNMARK`, удаление `ip rule` + flush таблиц DirectRoute, закрытие netlink-сокетов, удаление PID-файла

### Архитектурная схема (DNS-канал)

```
DNS-ответ dnsmasq → клиент (любой интерфейс: br0/WG/VPN/PPP/IPsec/туннель)
   |
   v
[dev_queue_xmit_nit() → ptype_all]    ← ETH_P_ALL обязателен
   |
   v
[AF_PACKET SOCK_DGRAM/ETH_P_ALL fd4/fd6
 ядро отдаёт L3-пакет без канального заголовка]
   |
   v
[L3-BPF: версия IP (ниббл) + proto + sport==53]
   |
   v
[process_dns_packet: парсинг DNS]
   |
   v
[Добавление новых IP в ipset через netlink]
   |
(ConntrackFlush=true && новые IP)
   |
   v
[conntrack_flush_request: IP → pending-буфер, старт async DUMP]
   |
   v
[epoll EPOLLIN на ct-fd → conntrack_process: чанки DUMP между DNS-пакетами,
 DELETE (fire-and-forget) по совпадению dst-IP с pending]

[Исходящий трафик клиента]
   → iptables/mangle PREROUTING
   → CONNMARK set-xmark по ipset dst match
   → CONNMARK restore-mark
   → ip rule fwmark → table X → default via <gw> dev <interface>
```

### Файловая структура (25 файлов `.c`)

| Файл | Назначение |
|------|------------|
| `src/main.c` | Точка входа, event loop (epoll), обработка DNS |
| `src/packet_capture.c` | AF_PACKET SOCK_DGRAM захват DNS (L3-BPF) |
| `src/iptables.c` | CONNMARK-правила, unified targets |
| `src/routing.c` | DirectRoute: ip rule, ip route, интерфейсы |
| `src/watchlist.c` | Парсинг domain.conf, матчинг доменов, sort_policies |
| `src/config.c` | Парсинг hrneo.conf + config_generate |
| `src/args.c` | Парсинг CLI, наложение на config |
| `src/params.c` | PARAMS[] — таблица описания параметров (single source of truth для config/args/help/genconfig) |
| `src/ipset_nl.c` | Низкоуровневая работа с ipset через netlink |
| `src/conntrack.c` | Сброс conntrack-записей через netlink: асинхронный DUMP (epoll) + DELETE по dst-IP из pending-буфера (DNS-канал) и точечный DELETE по 5-tuple (L7-канал, TCP и UDP/QUIC) |
| `src/dns.c` | Парсинг DNS-ответов (A, AAAA, CNAME) |
| `src/log.c` | Логирование (console/file/syslog/off) |
| `src/util.c` | Хеш-таблица доменов, chunked pool, fork/exec |
| `src/rci.c` | HTTP/JSON взаимодействие с API Keenetic |
| `src/signal_handler.c` | `signal_mgr_t` (signalfd + timerfd manager) |
| `src/geodat.c` | Парсинг GeoIP/GeoSite .dat файлов (protobuf) |
| `src/probe_tls.c` | Stateless парсер TLS ClientHello → SNI |
| `src/probe_http.c` | Stateless парсер HTTP request → Host |
| `src/probe_quic.c` | QUIC CRYPTO-walker: дешифровка Initial-пакета (v1/v2), HKDF + AES-128-CTR, ACK-frame skip → SNI; выдаёт CRYPTO-фрагмент для реассамблеции |
| `src/quic_crypto.c` | Pure-C SHA-256, HMAC-SHA256, HKDF-Expand-Label, AES-128-ECB/CTR (без AF_ALG, без libcrypto) |
| `src/bogon.c` | Фильтр служебных IPv4/IPv6 диапазонов |
| `src/nflog_capture.c` | NFLOG через raw NETLINK_NETFILTER (subsys ULOG=4, без libnetfilter_log) |
| `src/l7_dispatch.c` | Fail-fast диспетчер пакетов → probe → reasm; UDP/443 ветка для QUIC |
| `src/l7_firewall.c` | WAN-резолв, init_module, iptables NFLOG-правила (FORWARD+OUTPUT, TCP + UDP/QUIC) |
| `src/tcp_reasm.c` | 5-tuple реассамблеция длинных ClientHello: TCP-сегменты и QUIC CRYPTO-фрагменты (общий пул, ключи разделены битом family 0x80) |
| `include/hrneo.h` | Основные структуры, константы, inline `fnv1a_hash` |
| `include/*.h` | Заголовочные файлы для каждого модуля |
| `Makefile` | Сборка для mipsel, mips, aarch64, native |

---

## 2. Точка входа: `src/main.c`

### Константы (`include/hrneo.h`)

| Константа | Значение | Назначение |
|-----------|----------|------------|
| `DEFAULT_CONFIG_PATH` | `"/opt/etc/HydraRoute/hrneo.conf"` | путь к конфигу |
| `DEFAULT_PID_FILE` | `"/var/run/hrneo.pid"` | путь к PID-файлу |
| `DEFAULT_API_PORT` | `79` | порт RCI |
| `IPSET_HASH_TYPE` | `"hash:net"` | тип создаваемых ipset |
| `SOCKET_READ_BUFFER` | 1 МБ | `SO_RCVBUF` для AF_PACKET |
| `NF_COMMIT_INTERVAL_MS` | `3000` | пауза между попытками коммита; в ней SIGUSR1 игнорируются |
| `RCI_TIMEOUT_SEC` | `10` | таймаут RCI-запроса |
| `IPSET_CHUNK_SIZE` | `256` | размер батча ipset |
| `IPSET_DEFAULT_MAXELEM` | `262144` | fallback при `IpsetMaxElem=0` в `add_cidr_to_ipsets` |
| `POOL_CHUNK_SIZE` | `256 * 1024` | размер одного чанка string pool |
| `IPSET_ERR_EXIST` | `4103` | netlink-код «запись уже есть» |
| `IPSET_ERR_HASH_FULL` | `4101` | netlink-код «лимит maxelem» |
| `MAX_CNAME_CHAIN` | `16` | глубина BFS по CNAME |
| `DOMAIN_HT_BUCKETS` | `8192` | бакетов в хеш-таблице доменов |
| `MAX_GEO_FILES` | `16` | максимум `GeoIPFile`/`GeoSiteFile` |
| `MAX_POLICY_ORDER` | `64` | максимум целей в `PolicyOrder` |
| `MAX_INTERFACES` | `64` | максимум интерфейсов DirectRoute |

> В `hrneo.h` **НЕТ** `arena_t` / `ARENA_SIZE` — все временные буферы статические/на стеке.

### `config_t` (29 полей)

См. `src/params.c` и `docs/HRNEO.CONF.md`. Поля:

`auto_start`, `watchlist_path`, `clear_ipset`, `cidr_enabled`, `cidr_file_path`, `ipset_enable_timeout`, `ipset_timeout`, `log_level`, `log_file_path`, `direct_route_enabled` (default 1), `interface_fwmark_start` (12289), `interface_table_start` (301), `global_routing`, `conntrack_flush` (1), `ipset_maxelem` (262144), `geo_ip_files[16][512]`+counter, `geo_site_files[16][512]`+counter, `policy_order[64][64]`+counter, `l7_capture_enabled` (0), `l7_nflog_group` (210), `l7_enable_tls` (1), `l7_enable_http` (1), `l7_connbytes_max` (8), `l7_wan_interface[32]`, `l7_tcp_reasm_enabled` (1), `l7_tcp_reasm_max_entries` (256), `l7_tcp_reasm_ttl_sec` (5), `l7_enable_quic` (1).

### Глобальные переменные `main.c`

```c
config_t                g_config;
domain_hashtable_t     *g_all_targets;
ipset_manager_t         g_ipset_mgr;
volatile int            g_shutdown;
direct_route_manager_t  g_drm;
int                     g_drm_active;
unified_target_t        g_all_sorted[MAX_POLICY_ORDER + MAX_INTERFACES];
int                     g_all_sorted_count;
conntrack_mgr_t         g_conntrack = { .fd = -1, .del_fd = -1 };
nflog_capture_t         g_nflog;
int                     g_l7_active;
char                    g_l7_wan[MAX_INTERFACE_NAME];
tcp_reasm_t             g_reasm;
int                     g_reasm_active;
```

### `main()` — последовательность старта

1. `args_parse(argc, argv)` — парсинг CLI
   - `--version`/`-v`: `return 1` (`main → 0`)
   - `--help`/`-h`: `return 2 → 0`
   - `--genconfig [path]`: `return 3 → main` вызывает `config_generate(args.genconfig_target)`
   - `--keenetic <token>`: `return 4 → main` вызывает `config_set_keenetic_token(cfg_path, args.keenetic_token)`
   - ошибка: `return -1 → 1`
2. `sigprocmask(SIG_BLOCK)` для `SIGINT`/`SIGTERM`/`SIGUSR1`
3. `config_read()` — путь из `args.config_path` или `DEFAULT_CONFIG_PATH`; явный `--config` при недоступном файле → выход 1
4. `args_apply()` — наложение CLI-флагов (только `set_mask`-биты)
5. Если `!auto_start` → `return 0`
6. `log_setup()` + `LOG_INFO "HRNeo v%s starting"`
6a. `rci_token_bootstrap(cfg_path)` — **до** `create_pid_file`: проба `GET /rci/show/version` с токеном и без определяет режим авторизации; если прошивка требует токен, а рабочего нет — выпуск нового через `ndmc` и запись в `hrneo.conf` (см. раздел 13)
6b. `create_pid_file()`
7. `ht_create()` — создание хеш-таблицы доменов
8. Если DirectRoute: `drm_init()`, `drm_scan_interfaces()`, `parse_watchlist_classified()`. Иначе: `parse_watchlist()`, `get_unique_names()`
9. `CIDR=true`: `parse_cidr_policy_headers()` — имена из заголовков `/Name` CIDR-файла раскладываются по `drm_classify_target` в `iface_names[]`/`policy_names[]`; `LOG_INFO "CIDR: added policy 'X'"` для каждой новой политики
10. GeoSite файлы заданы: `parse_geosite_rules()` — цели `geosite:`-правил раскладываются так же; `LOG_INFO "GeoSite: added policy 'X'"` для каждой новой политики
10a. Если DirectRoute: для каждого имени из `iface_names[]` — `drm_allocate_fwmark()`, `drm_allocate_table_id()`, `drm_register_route()`
11. `sort_policies()` для `policy_names` с учётом `PolicyOrder`
12. `g_all_sorted[]`: `all_names = policy_names + iface_names`, `sort_policies()` на объединении; `unified_target_t = {pair (ipv4/ipv6 имена), is_interface, fwmark}`
13. `LOG_INFO "Target order (%d):"` — вывод порядка целей
14. `rci_create_policies()` — только для `policy_names` (один POST: массив `parse`-команд + `save` последним элементом)
15. `ipset_manager_init()` + установка `g_ipset_mgr.default_timeout` (из `IpsetEnableTimeout`/`IpsetTimeout`) + `initialize_ipsets()` — создание/очистка ipset-пар для всех `g_all_sorted`
16. `add_cidr_to_ipsets()` — если `CIDR=true` и `cidr_file_path` задан
17. `build_geosite_domain_map()` — если `gs_count > 0` (правила `geosite:` распарсены один раз на шаге 10 и переиспользуются)
18. `drm_setup_all_routes()` — `ip rule` + `ip route` для DirectRoute
19. Если `conntrack_flush` — `conntrack_mgr_init()` (при ошибке flush отключается)
20. `pkt_capture_init()` — два `AF_PACKET SOCK_DGRAM/ETH_P_ALL` сокета (`fd4`, `fd6`)
21. Если `l7_capture_enabled`: `l7_firewall_resolve_wan` (при неудаче — L7 отключается с `LOG_WARN`, DNS-only); `l7_firewall_load_nflog_modules` (`nfnetlink_log`+`xt_NFLOG` через `init_module(2)`; при неудаче — L7 отключается, DNS-only, **без fallback**). Иначе: `l7_firewall_load_kmod("xt_connbytes")`; `l7_dispatch_set_enable` (с флагами tls/http/quic); при `l7_tcp_reasm_enabled` — `tcp_reasm_init` + `l7_dispatch_set_reasm` (`g_reasm_active=1`); `nflog_capture_init` → `g_l7_active=1`. Правила NFLOG **не ставятся здесь** — они входят в общий batch коммитера (шаг 24)
22. `signal_mgr_init()` — `sigprocmask` + `signalfd` + `timerfd`
23. `epoll_create1()` — регистрация `cap.fd4`, `cap.fd6`, `signals.sig_fd`, `signals.timer_fd`; при активном conntrack flush — `g_conntrack.fd` (async DUMP); при `g_l7_active` — `nflog_fd`; при `g_reasm_active` — `reasm_gc_fd` (`timerfd` 1s)
24. `commit_run()` — первый коммит netfilter (тот же путь, что и по SIGUSR1, с тем же ретраем через фиксированные 3 с)
25. Основной цикл `epoll_wait` (`events[8]`)
26. **Cleanup:** `signal_mgr_close` → `l7_firewall_remove` + `nflog_capture_close` → `tcp_reasm_close` (если `g_reasm_active`) → `pkt_capture_close` → `conntrack_mgr_close` → `drm_cleanup_all_routes` → `cleanup_connmark_rules` → `ipset_manager_close` → `ht_destroy` → `remove_pid_file` → `log_close`

---

## 3. DNS-детекция: AF_PACKET захват

**Файл:** `src/packet_capture.c`, `include/packet_capture.h`

### `pkt_capture_t` (структура)

| Поле | Тип | Назначение |
|------|-----|------------|
| `fd4` | `int` | AF_PACKET сокет с L3-BPF для IPv4 DNS |
| `fd6` | `int` | AF_PACKET сокет с L3-BPF для IPv6 DNS |
| `callback` | `pkt_capture_cb` | колбэк `(const uint8_t *pkt, int pkt_len, void *user_data)` |
| `user_data` | `void *` | произвольный контекст |
| `recv_buf` | `uint8_t[65536]` | буфер приёма |

### `pkt_capture_init(cap, cb, user_data)`

1. Создаёт два сокета через `open_capture_socket()`:

   ```c
   socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_ALL))
   ```

2. `SO_RCVBUF = SOCKET_READ_BUFFER` (1 МБ)
3. `SO_ATTACH_FILTER` с классической BPF-программой

### Почему `SOCK_DGRAM` (а не `SOCK_RAW`)

Ядро снимает канальный (L2) заголовок и отдаёт пакет с сетевого (IP) уровня единообразно для интерфейсов любого типа — Ethernet (`br0`), PPP, `ARPHRD_NONE` (WireGuard `nwg0`, VPN-сервер `t2s*`, IPsec `xfrms*`), туннели. Поэтому DNS-ответы VPN-клиентам (не-Ethernet интерфейсы, нет 14-байтного Ethernet-заголовка) больше не теряются. Фильтры работают от смещения 0 (IP-заголовок), а не от Ethernet.

### BPF-фильтры (L3, данные начинаются с IP-заголовка)

- **`bpf_v4_dns`:** версия IP по верхнему нибблу байта 0 == 4, proto (байт 9) == UDP(17) или TCP(6), `src_port == 53` (индексированная загрузка halfword по `X=IHL×4`)
- **`bpf_v6_dns`:** версия IP == 6, `next_header` (байт 6) == UDP(17) или TCP(6), `src_port` читается из halfword по фиксированному смещению 40 (IPv6-заголовок) == 53 (extension-заголовки не разбираются — поведение как у прежнего фильтра)

### Почему `ETH_P_ALL`

Ядро Linux доставляет исходящие пакеты через `dev_queue_xmit_nit()` только обработчикам `ptype_all`. `ETH_P_IP`/`ETH_P_IPV6` регистрируются в `ptype_base` и не получают исходящие пакеты физических интерфейсов. `ETH_P_ALL` регистрируется в `ptype_all` → перехватывает DNS-ответы dnsmasq → клиентам.

### `pkt_capture_process(cap, fd)`

- `recvfrom()` с `sockaddr_ll` (адресный буфер; `sll_hatype` не анализируется)
- При `SOCK_DGRAM` канального заголовка нет ни для одного типа интерфейса → смещение не вычисляется, callback вызывается с `recv_buf` (IP-пакет со смещения 0)

### `pkt_capture_close(cap)`

Закрывает `fd4` и `fd6`.

---

## 4. Обработка DNS-пакетов: `src/dns.c` + `src/main.c`

### Структуры DNS (`include/dns.h`)

```c
dns_answer_t { domain[256]; ip[16]; family; }   // один A/AAAA-ответ
dns_cname_t  { source[256]; target[256]; }      // одна CNAME-запись
dns_result_t {
    answers[DNS_MAX_ANSWERS]; answer_count;
    cnames[DNS_MAX_CNAMES];   cname_count;
}

#define DNS_MAX_ANSWERS  128
#define DNS_MAX_CNAMES    32
```

### `extract_dns_payload(pkt, pkt_len, dns_len)`

1. Определяет версию IP (4/6), вычисляет `ip_hdr_len` и `transport_offset`
2. Проверяет `src_port == 53`
3. Определяет протокол (UDP/TCP)
4. TCP: пропускает 2-байтовый length prefix, `dns_len = MIN(prefix, pkt_remaining)`
5. Возвращает указатель на DNS-данные

### `dns_parse_response(dns_data, dns_len, result)`

1. Проверяет `DNS_FLAG_QR` (response)
2. Пропускает Question-секцию
3. Итерирует Answer-секцию: `TypeA` → `answers[]`, `TypeAAAA` → `answers[]`, `TypeCNAME` → `cnames[]`
4. `dns_decode_name`: декодирует DNS-имена с поддержкой compression pointers (до 128 hop защиты)

### `process_dns_packet(pkt, pkt_len, user_data)` (`main.c`)

1. `extract_dns_payload` + `dns_parse_response` → `dns_result_t` (статическая переменная в функции)
2. Итерирует уникальные домены (`processed[64][256]` на стеке) — для каждого:
   - Сбор IPv4/IPv6 батчей из `answers` (до 32 каждого семейства)
   - `process_hostname_event(domain, result.cnames, result.cname_count, ..., "DNS")` — общий хелпер с L7-каналом; CNAME-записи передаются как `dns_cname_t` напрямую из результата парсинга, без промежуточного копирования

### `process_hostname_event(domain, cnames, ipv4_batch, ipv4_count, ipv6_batch, ipv6_count, source_tag, allow_conntrack_flush)`

Возвращает `int` — число реально добавленных (новых) IP (`all_new_count`).

1. `match_domain_with_cname` → `ipset_name` (или `NULL` — пропуск)
2. `LOG_MATCH "[<tag>] <domain> -> <ipset>"` (или `"<domain> via <matched_domain> -> <ipset>"` при CNAME)
3. `ipset_add_batch` для IPv4 (`setname`, `with_timeout=1`)
4. `ipset_add_batch` для IPv6 (`setname + "v6"`, `with_timeout=1`)
5. `LOG_PROCESSED` для каждого реально добавленного (нового) IP
6. `conntrack_flush_request()` если `allow_conntrack_flush=1` И `conntrack_flush=1` И есть новые IP — новые IP кладутся в pending-буфер, DUMP+DELETE выполняются асинхронно в epoll-цикле (`conntrack_process`), обработка DNS не блокируется. DNS-канал передаёт `allow_conntrack_flush=1`; L7-канал — `0` (полный DUMP за L7 не выполняется, вместо него — точечный DELETE по 5-tuple в `process_hostname_event_l7`).

### `process_hostname_event_l7(host, proto, conn)`

Обёртка из L7-канала (вызывается из `l7_dispatch.c`). Принимает `const l7_conn_t *conn` (семейство, IP/порты клиента и сервера). Строит `parsed_cidr_t` из `conn->server_ip`/`conn->family`, вызывает `process_hostname_event(..., /*allow_conntrack_flush*/0)` с тегом `"TLS-SNI"` / `"HTTP-Host"`. Если возврат `> 0` (IP добавлен впервые) И `conntrack_flush=1` — `conntrack_delete_conn(&g_conntrack, conn)`: точечное удаление conntrack-записи триггернувшего соединения по полному 5-tuple (client↔server, TCP-порты). L7 ловит ClientHello уже **установленного** соединения, поэтому запись всегда существует и удаление надёжно вынуждает реконнект по политике (см. §18.3). Полного DUMP таблицы здесь нет — один netlink-DELETE, O(1).

---

## 5. Матчинг доменов: `src/watchlist.c`

### `match_domain(ht, policy_order, order_count, domain, domain_len)`

1. Точное совпадение через `ht_lookup()`
2. Суффиксный поиск: для каждой точки в домене проверяет parent-домен
3. Приоритет: `policy_order` (меньше индекс = важнее); тай-брейкер по специфичности (длиннее = специфичнее)
4. Точное: `specificity = domain_len + 1`; суффиксное: `specificity = suffix_len`

### `match_domain_with_cname(ht, policy_order, order_count, domain, cnames, cname_count, matched_domain)`

BFS-обход CNAME-цепочки (до `MAX_CNAME_CHAIN=16` шагов). Поиск двунаправленный: для каждого текущего домена проверяются как `cnames[i].from == current` (forward), так и `cnames[i].to == current` (backward). Защита от циклов через `visited_hashes` (FNV-1a). Возвращает первый совпавший `ipset_name` и `matched_domain` (через out-параметр).

### `parse_watchlist_lines(path, on_target, on_domain, user)`

Единый построчный разборщик `domain.conf`:

- Строки читаются через `getline()` (динамический буфер) — длина строки не ограничена
- Цель (после последнего `/`) копируется в `target_buf[64]`; домены-часть режется in-place и разбивается `strtok_r` по запятой
- `on_target` вызывается один раз на строку; `on_domain` — для каждого не-`geosite` домена (уже lowercase)
- `geosite:`-записи пропускаются на этом этапе

### `parse_watchlist(path, ht)`

Обёртка над `parse_watchlist_lines`; `ht_insert(match_subs=1)` для каждого домена.

### `parse_watchlist_classified` (`routing.c`)

`on_target` классифицирует через `drm_classify_target` и сортирует в `policy_names[]`/`iface_names[]`; `on_domain` делает `ht_insert`. Итог: `LOG_INFO "domain.conf: %d policies, %d interfaces"`.

### `sort_policies(names, count, order, order_count)`

- Каждому имени присваивается приоритет: индекс в `order` (отсутствует → `order_count`)
- Один `qsort` по составному ключу `(priority, strcmp)`: элементы из `order` идут первыми в его порядке, остальные — алфавитно
- Буферы рассчитаны на `MAX_POLICY_ORDER + MAX_INTERFACES` (128) элементов — функция безопасна для объединённого массива policy + iface
- Элементы `order`, отсутствующие в `names` → `LOG_WARN`

> `parse_cidr_policy_headers` перенесён в `src/geodat.c` — вся грамматика CIDRfile живёт в одном модуле (см. раздел 12).

### PolicyOrder — единственный механизм приоритезации целей

Политики Keenetic и цели-интерфейсы DirectRoute равноправны: `sort_policies`
работает по единому массиву без различия типов, `get_policy_priority` — по
одному имени. Работает на **ДВУХ уровнях независимо**:

**1) Порядок CONNMARK-правил в `iptables/mangle/PREROUTING`**

`main` вызывает `sort_policies` дважды: для `policy_names` (для `rci_create_policies`) и для объединённого `all_names` (policy + iface вместе) — результат пишется в `g_all_sorted[]`. `apply_unified_connmark_rules` итерирует этот массив последовательно и добавляет правила `CONNMARK` в этом порядке через `iptables-restore --noflush`. Поскольку `iptables` проверяет правила сверху вниз и берёт первое совпадение, при попадании пакета в несколько `ipset` одновременно (например, IP принадлежит сразу `/HydraRoute` и `/RU` в `ip.list`, или один IP пришёл в DNS-ответах разных доменов разных политик) выигрывает цель, стоящая раньше в `PolicyOrder`.

**2) Выбор политики при матчинге домена (`match_domain` через `get_policy_priority`)**

Если домен зарегистрирован сразу в нескольких целях (например, в watchlist прописано `google.com/HydraRoute` и `mail.google.com/RU`, или CNAME-цепочка проходит через домены разных политик), `match_domain` среди всех совпадений выбирает с минимальным индексом в `policy_order`; при равных priority — с большей `specificity` (длина совпавшего суффикса; точное совпадение = `len+1`, выигрывает над любым суффиксным). Цели не из `policy_order` получают `priority=order_count` («последние»).

Имена политик Keenetic и имена сетевых интерфейсов смешиваются в одном `PolicyOrder`; hrneo автоматически различает их через `drm_classify_target` по `/sys/class/net`.

`SIGUSR1` не перечитывает `hrneo.conf` и сам `PolicyOrder`; `apply_unified_connmark_rules` пересоздаёт правила в **уже** загруженном порядке `g_all_sorted[]`. Для применения нового `PolicyOrder` требуется `neo restart`.

---

## 6. Хеш-таблица доменов: `src/util.c`

### `pool_chunk_t`

```c
struct pool_chunk {
    struct pool_chunk *next;          // следующий чанк
    size_t             used;          // байт занято в чанке
    char               data[POOL_CHUNK_SIZE];  // 256 КБ данных
};
```

### `domain_hashtable_t`

| Поле | Назначение |
|------|------------|
| `buckets[8192]` | цепочки `domain_node_t` |
| `count` | количество записей |
| `pool_head`, `pool_tail` | linked list чанков (аллокатор строк и нод) |
| `ipset_name_cache[MAX_POLICY_ORDER][64]` | кэш строк-имён политик |
| `ipset_name_ptrs[MAX_POLICY_ORDER]` | соответствующие указатели в pool |
| `ipset_name_count` | размер кэша |

### Функции

**`ht_create()`** — создаёт таблицу + первый `pool_chunk_t`.

**`ht_insert(ht, domain, domain_len, ipset_name, match_subs)`:**

- FNV-1a хеш → индекс бакета
- Проверка дубликата домена (возврат 0 без изменений)
- Дедупликация `ipset_name`: поиск в `ipset_name_cache[]` (`O(MAX_POLICY_ORDER)`), переиспользует ptr
- Нода и строки хранятся в `pool_chunk_t` через `ht_pool_alloc()`
- Возвращает `1` при вставке, `0` при дубле, `-1` при ошибке аллокации

**`ht_lookup(ht, domain, domain_len)`** — `O(1)` средний.

**`ht_destroy(ht)`** — освобождает чанки linked list + сам `ht`.

### Вспомогательные функции

- `to_lower_inplace()` — ASCII lowercase in-place
- `trim_whitespace()` — обрезка пробелов
- `fnv1a_hash()` — inline в `hrneo.h`
- `mkdir_p()` — рекурсивное создание каталогов
- `run_command_output()` — `fork`/`execvp` с захватом `stdout`+`stderr`
- `run_command_stdin()` — `fork`/`execvp` с подачей `stdin`

---

## 7. Управление ipset: `src/ipset_nl.c`

### `ipset_manager_t`

| Поле | Назначение |
|------|------------|
| `fd` `int` | netlink-сокет (`NETLINK_NETFILTER`, long-lived) |
| `seq`, `pid` | для netlink-сообщений |
| `default_timeout` | единый timeout (сек) для DNS-path ADD всех сетов; 0 = без timeout. Устанавливается в `main` из `IpsetEnableTimeout`/`IpsetTimeout` |
| `set_names[IPSET_MAX_SETS=512][64]` | кэш имён существующих ipset |
| `set_count` | количество кэшированных имён |

### `ipset_create(mgr, name, type, family, timeout, maxelem)`

- `ipset_query_revision()` — `IPSET_CMD_TYPE` через netlink: отправляет TYPE-запрос, парсит ответ, извлекает `IPSET_ATTR_REVISION` (при ошибке → 0)
- `IPSET_CMD_CREATE` через netlink с флагами `NLM_F_CREATE | NLM_F_EXCL`; атрибуты: `PROTOCOL`, `SETNAME`, `TYPENAME`, `REVISION`, `FAMILY`
- DATA-атрибут добавляется если `timeout > 0` OR `maxelem > 0`
- `errno=17` (`EEXIST`) → `LOG_DEBUG "Set %s already exists"`, добавляет в кэш, возвращает 0
- Прочие ошибки: `LOG_ERROR` + возврат `errno`
- При успехе: `LOG_DEBUG "Set %s created"`, добавляет в `set_names` кэш

### `ipset_flush(mgr, name)`

`IPSET_CMD_FLUSH` через netlink.

### `ipset_add_batch(mgr, set_name, entries, count, with_timeout, new_count, new_indices)`

1. `has_timeout = mgr->default_timeout > 0`
2. Фильтрует service IP через `is_service_ip()` (`LOG_FILTERED`)
3. Формирует netlink-сообщения через `build_ipset_add_msg()`: `TIMEOUT`-атрибут добавляется при `has_timeout=1`; значение = `default_timeout` при `with_timeout=true`, иначе явный `0` (постоянная запись CIDR-пути)
4. Чанки по `IPSET_CHUNK_SIZE=256`: send все сообщения чанка, затем recv все ответы
5. `with_timeout=true`: `NLM_F_EXCL` (повторное добавление → `IPSET_ERR_EXIST` без обновления `timeout`); `new_indices` заполняется только при `with_timeout=true`
6. `with_timeout=false`: `NLM_F_CREATE` без `NLM_F_EXCL`; `new_indices` не заполняется
7. Обработка ошибок netlink ack:
   - `err->error == 0` → запись добавлена, индекс пишется в `new_indices` при `with_timeout=1`
   - `IPSET_ERR_HASH_FULL` (4101) → `LOG_WARN "ipset '%s' full"`
   - `IPSET_ERR_EXIST` (4103) → молча игнорируется
   - Прочие коды → `LOG_DEBUG "Netlink ADD error: errno=%d"`

### Прочие функции

- `ipset_refresh_set_list()` — `ipset list -n` → заполняет `set_names`
- `ipset_set_exists()` — линейный поиск по `set_names`
- `ipset_add_to_cache()` — добавляет имя в `set_names`

### `is_service_ip()`

- IPv4: первый октет == 0 или 127
- IPv6: `::` (unspecified), `::1` (loopback)

---

## 8. Маршрутизация и маркировка

### A) Policy-Based (через политики Keenetic)

**Файл:** `src/iptables.c`, функция `apply_unified_connmark_rules()`.

1. `get_br0_global_ipv6()`: `ip addr show br0` — получает IPv6-сеть `scope global` (нужна только она: IPv6-правила для политик ставятся лишь при её наличии)
2. Оба семейства обрабатываются единым кодом через массив дескрипторов `connmark_family_t[2]` (`{ipt_cmd, restore_cmd, dump, batch}`: `iptables`/`iptables-restore` и `ip6tables`/`ip6tables-restore`); для каждого семейства читаются **только разбираемые цепочки**: `-w -t mangle -S PREROUTING`, а при включённом L7 дополнительно `-S FORWARD` и `-S OUTPUT`, склеенные в один буфер. Полная таблица не читается: её объём задаёт роутер (по 3 правила `_NDM_HOTSPOT_PREROUTING_MANGL` на каждую привязку устройства к политике). Ошибка или обрезание вывода → `-1`
3. Дамп читается **до** обращений к RCI. Для каждой цели `find_mark_in_rules()` по дампу каждого семейства (строка обязана начинаться с `-A PREROUTING `) даёт факт наличия правил и марку в них
4. markID запрашивается **лениво**: только если правил хотя бы в одном семействе нет — либо если идёт `startup_audit`, режим первого успешного коммита. Интерфейсные цели RCI не используют вовсе (`mark = fwmark`). Если правила на месте и аудит уже пройден, цель пропускается без единого сетевого вызова
   - `RCI_MARK_TRANSPORT` / `RCI_MARK_DENIED` → цель помечается неполной и пропускается (без раннего выхода: удаление правил возможно только после получения актуальной марки, поэтому окна «удалили и вышли» нет)
   - `RCI_MARK_ABSENT` → `incomplete=1`; **в режиме аудита** оставшиеся правила такой цели удаляются как осиротевшие: политики уже нет, а её markID Keenetic выдаст следующей созданной политике (docs/MARKID_DRIFT.md)
   - в режиме аудита марка в правилах сверяется с RCI; расхождение → `iptables_delete_rules_matching()` и пересоздание. На последующих коммитах сверки нет, достаточно факта наличия правил
   - IPv6-правило для политики не создаётся, если у `br0` нет глобального IPv6
5. Если L7 активен — `l7_firewall_emit_rules()` дописывает недостающие NFLOG-правила `FORWARD`/`OUTPUT` **в тот же batch** (наличие определяется по тому же дампу)
6. Каждый непустой batch → один вызов `iptables-restore --noflush` / `ip6tables-restore --noflush`. Ненулевой код возврата или переполнение batch → `-1`
7. Возврат: `0` — таблица приведена в целевое состояние полностью; `-1` — коммитер повторит через 3 с

#### Правила CONNMARK (`GlobalRouting=false`)

```
-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0
   -m connmark --mark 0x0/0xffffffff
   -m set --match-set <ipset> dst
   -j CONNMARK --set-xmark 0x<mark>/0xffffffff

-A PREROUTING -m set --match-set <ipset> dst
   -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
```

`GlobalRouting=true`: условие `! --mark 0xffffaa0/0xffffff0` убирается.

#### Guard `-m connmark --mark 0x0/0xffffffff`

Маска покрывает **весь** марк. Это условие «соединение ещё никем не
промаркировано» — оно и реализует «первое совпадение выигрывает» для целей
любого типа: `markID` политики (`0xffffaaa`) и `fwmark` интерфейса (`0x3001`)
проверяются одинаково.

Маска обязана быть полной. `fwmark` целей-интерфейсов
(`InterfaceFwmarkStart`, по умолчанию `12289` = `0x3001`) лежит в младших 16
битах, поэтому при маске `0xffff0000` условие оставалось истинным и **после**
маркировки: правило каждой следующей цели перезаписывало марк предыдущей, и при
попадании IP сразу в несколько `ipset` выигрывала последняя цель, а не первая по
`PolicyOrder`. Для политик Keenetic баг не проявлялся — их марки заняты в
старших битах.

Следствие: марк ставится на соединение **ровно один раз**, дальше работает
только `--restore-mark`. Соединение, установленное до попадания IP в нужный
`ipset`, доживает на прежнем маршруте до истечения conntrack-записи и не
перескакивает в середине сессии. Для политик так было всегда; цели-интерфейсы
перемаркировывались на каждом пакете — теперь поведение общее.

Уровнем выше стоит **привязка устройства к политике в самом Keenetic**:
`ndm` ставит марк `0xffffaaX` до правил hrneo, и условие
`! --mark 0xffffaa0/0xffffff0` заставляет hrneo уступить целиком. `PolicyOrder`
на этот уровень не влияет — снимается только `GlobalRouting=true`.

#### `unified_target_t` (`include/iptables.h`)

| Поле | Тип | Назначение |
|------|-----|------------|
| `pair` | `ipset_pair_t` | ipv4/ipv6 имена |
| `is_interface` | `int` | флаг интерфейса DirectRoute |
| `fwmark` | `int` | назначенный fwmark (для интерфейсов) |

`g_all_sorted[]` объединяет политики и интерфейсы в единый отсортированный массив.

`cleanup_connmark_rules(pairs, count)`: удаляет CONNMARK-правила из `mangle/PREROUTING`.

### Б) DirectRoute (прямая маршрутизация на интерфейс)

**Файл:** `src/routing.c`.

#### `direct_route_manager_t`

| Поле | Назначение |
|------|------------|
| `config` | `*config_t` |
| `interfaces[MAX_INTERFACES=64]` | `interface_info_t (name, state)` |
| `interface_count` | счётчик интерфейсов |
| `routes[MAX_INTERFACES]` | `interface_route_t (interface_name, ipset_pair, fwmark, table_id)` |
| `route_count` | счётчик маршрутов |
| `next_fwmark`, `next_table_id` | следующий свободный fwmark/table_id |

#### Инициализация

1. `parse_watchlist_classified()` → раздельные `policy_names[]`, `iface_names[]`
2. Для каждого `iface`: `drm_allocate_fwmark()` + `drm_allocate_table_id()` + `drm_register_route()` (создаёт `ipset_pair`: `ipv4 = iface_name`, `ipv6 = iface_name + "v6"`)

#### Активность интерфейса

`drm_iface_active(state)`: `"up"` или `"unknown"` — активен. DOWN → `blackhole`-маршрут в таблице. Установка маршрута по состоянию инкапсулирована в `drm_install_route(iface, table_id, active, ipv6)` — единая функция и для стартовой настройки, и для реакции на смену состояния.

#### Настройка маршрутов (`drm_setup_all_routes`)

```
ip -4|-6 rule    add     priority N fwmark 0x<mark> table <tableID>
ip -4|-6 route   replace default via <gw> dev <interface> table <tableID>
ip -4|-6 route   replace blackhole default table <tableID>    # если DOWN
```

Семейство задаётся явным `-4`/`-6` на каждом вызове `ip`: без него селектор
`default` в командах вида `route show table all default dev X` игнорируется и в
выборку попадают маршруты обоих семейств.

**Шлюз (`drm_lookup_gateway`).** Перед установкой маршрута nexthop ищется в
`ip -4|-6 route show table all default dev <interface>` — берётся первая строка
с ` via `, строки собственной таблицы (`table <tableID>`) пропускаются, чтобы не
зациклиться на своём же прошлом значении при смене шлюза. Найден → `default via
<gw> dev <iface>`, не найден → `default dev <iface>` как раньше.

Без этого DirectRoute на Ethernet-WAN не работал: `default dev eth3 scope link`
заставляет ядро искать nexthop равным самому адресу назначения и слать ARP на
публичный IP в сеть провайдера. Туннели (PPP, WireGuard — `POINTOPOINT,NOARP`)
шлюза не имеют и работали, поэтому дефект был виден только на провайдерских
интерфейсах. Источник шлюза — per-interface таблицы NDMS (`16385`, `16393`, …),
они есть и для резервных WAN, не только для текущего дефолтного.

`replace` вместо `add`: идемпотентно без разбора `"File exists"` и переставляет
маршрут при смене шлюза (обновление адреса по DHCP). `"can't find device"` →
`blackhole` вместо ошибки.

**IP Rule Priority:** `9 - (table_id - table_start)`, минимум 1. На разрешение
коллизий не влияет — `fwmark` у каждого интерфейса свой, правила
взаимоисключающие.

#### Прочие функции

- `drm_scan_interfaces()` — читает `/sys/class/net/`, для каждого только `operstate`
- `drm_classify_target()` — линейный поиск по имени в `interfaces[]`
- `drm_lookup_state()` — состояние интерфейса по имени (`"unknown"` если не найден)
- `drm_update_used_states()` — обновляет `operstate` только для `routes[]`
- `drm_get_states(drm, states, count)` — снимок текущих состояний `routes[]` перед обновлением
- `drm_handle_state_changes(drm, old_states, old_count)` — сравнивает старые и новые; при изменении — `drm_update_route_on_state_change(iface, table_id, new_state)`: `drm_flush_routing_table(table_id)` + `drm_install_route` для обоих семейств

---

## 9. Обработчик сигналов: `src/signal_handler.c`

`signal_mgr_t { sig_fd, timer_fd }` — один контейнер для `signalfd` и `timerfd` коммитера.

### `signal_mgr_init(m)`

- `sigprocmask(SIG_BLOCK, ...)` повторно (`main` уже блокирует) — защита
- `signalfd(SFD_CLOEXEC)` → `m->sig_fd`
- `timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)` → `m->timer_fd`

### Прочие функции

- `signal_mgr_close(m)` — close обоих `fd`
- `signal_mgr_arm_timer(m, milliseconds)` — one-shot через `timerfd_settime`
- `signal_mgr_read_timer(m)` — `read()` expirations

`arm_timer` вызывается только из `commit_start`/`commit_run`, то есть либо при
неактивном цикле, либо сразу после `read_timer`. Обработчик сигнала таймер не
трогает, поэтому взвести уже сработавший, но ещё не прочитанный таймер нельзя —
блокирующий `read(timer_fd)` не может залипнуть.

### Логика обработки (`main.c`, epoll loop)

Коммитер netfilter — leading-edge цикл на одном `timer_fd`. Требование NDMS
(см. `NETFILTER_RACE.md`): накапливать вызовы `netfilter.d`, повторять при
любой ошибке записи. Ключевое ограничение сверху — задержка первой записи:
пока правил нет, а IP уже в ipset, новые соединения устанавливаются с маркой 0
и уходят мимо целевой политики навсегда (conntrack держит их до закрытия).
Поэтому первая запись выполняется без задержки.

Состояние цикла — один флаг `g_commit_active`.

**`SIGUSR1`:**

- `g_commit_active != 0` → сигнал игнорируется целиком (`LOG_DEBUG "SIGUSR1
  ignored, commit cycle active"`). Таймер **не** сбрасывается — это и есть
  защита от дребезга: пачка из ~30 хуков одного события ndm не порождает ни
  одной лишней записи и не сдвигает подтверждающую;
- иначе → `commit_start()`: `g_commit_active=1`, немедленный `perform_update()`
  (результат намеренно игнорируется — таблицу всё равно может затереть ndm
  в середине своей пачки), таймер на `NF_COMMIT_INTERVAL_MS`.

**`timer_fd`:** `signal_mgr_read_timer` → `commit_run()`:

- `perform_update()` = `rci_auth_recover` + `rci_create_policies` (если
  `g_policies_pending`); при `g_drm_active` — `drm_get_states` +
  `drm_update_used_states` + `drm_handle_state_changes` + `drm_setup_all_routes`
  (последний восстанавливает `ip rule`/`ip route` после NDMS: маршруты идемпотентны
  через `ip route replace`, `ip rule` — по «File exists»); всегда — `apply_unified_connmark_rules(..., &g_config,
  g_l7_active ? g_l7_wan : NULL)`
- возврат `0` → `LOG_INFO "netfilter rules committed"`, `g_commit_active=0`,
  цикл закончен; следующий SIGUSR1 запустит его заново
- возврат `-1` → таймер снова на `NF_COMMIT_INTERVAL_MS`, без роста интервала.
  Ретраи не заканчиваются: система самовосстанавливается без внешних событий

Итого на одно событие ndm — минимум две записи: немедленная и подтверждающая
через 3 с (она проходит уже после того, как пачка хуков отгремела). Вторая
почти всегда бесплатна: дампы совпадают, `iptables-restore` не запускается.

Стартовый коммит (шаг 24 инициализации) идёт через тот же `commit_start()` —
отдельного пути установки правил нет.

**`SIGINT`/`SIGTERM`:** `g_shutdown=1` → выход из epoll loop → cleanup.

---

## 10. Файл конфигурации: `src/config.c` + `src/params.c`

Формат: `key=value`, комментарии `#`, пустые строки игнорируются. `GeoIPFile` и `GeoSiteFile` могут повторяться (до `MAX_GEO_FILES=16`). `PolicyOrder` — через запятую, до `MAX_POLICY_ORDER=64`.

Описание параметров — таблица `PARAMS[]` в `src/params.c` (`param_def_t`: `config_key`, `cli_flag`, `type`, offset-ы в `config_t`, `set_bit`, `default_int`, `help_arg`, `help_text`, `help_default`). Один ряд на параметр, драйвит `config_read`, `args_parse`, `args_apply`, `print_help`, `config_generate`. Типы: `PT_BOOL`, `PT_INT`, `PT_INT_POS`, `PT_STRING`, `PT_PATH`, `PT_REPEAT_PATH`, `PT_POLICY_ORDER`.

Применение значения — единая функция `param_apply(cfg, p, val, strict)` (там же, в `params.c`): её используют и парсер конфига (`strict=0` — невалидное значение → `LOG_WARN`, остаётся дефолт; `PT_BOOL` лояльно трактует всё, кроме `true`, как `false`), и CLI (`strict=1` — невалидное значение → ошибка и выход 1). Числовые значения валидируются полностью (`strtol` + проверка остатка строки).

### `config_read(path, cfg)`

- `memset(cfg, 0)` + применение `default_int` / `help_default` для каждого `PARAMS[i]`
- `fopen(path)`; при ошибке возвращает `-1` (но `main` продолжит, если путь дефолтный)
- Построчно `key=value` через `param_apply(cfg, p, val, 0)`; невалидное значение → `LOG_WARN "Invalid %s value"` + дефолт

### `config_generate(target)`

- `target` пустой → `hrneo.conf` рядом с бинарём (`readlink /proc/self/exe → dirname`)
- `target`-каталог (или со слешем) → `<dir>/hrneo.conf`
- `target`-файл → записывается ровно по пути
- Записывает все 29 ключей с дефолтами; пустые multi-value ключи как `Key=`

> Полное описание ключей и поведения — в `docs/HRNEO.CONF.md`.

### Формат watchlist (`domain.conf`)

```
домен1,домен2,.суффикс,geosite:TAG/ПолитикаИлиИнтерфейс
```

Пример: `googlevideo.com,youtube.com,geosite:google/HydraRoute`

### Формат CIDR (`ip.list`)

```
##Описание блока (необязательно)
/ПолитикаИлиИнтерфейс
103.224.0.2/32
104.16.0.0/12
geoip:ru

##Отключённый блок
#/ПолитикаИлиИнтерфейс
45.67.123.19/32
```

#### Синтаксис блоков

- Активный блок начинается с `/ИмяПолитики` и завершается: пустой строкой, строкой `##...`, новым `/...` или новым `#/...`
- `##...` — одновременно комментарий и терминатор текущего блока
- `/...` — заголовок нового активного блока и терминатор предыдущего
- `#/...` — заголовок нового отключённого блока; записи внутри игнорируются
- Пустая строка — терминатор блока

#### Автоматически добавляемый раздел при превышении лимита ipset

```
##impossible to use
#/Too-big-geoip-tag
geoip:ru
```

---

## 11. CLI аргументы: `src/args.c`

### `cli_args_t` (`include/args.h`)

| Поле | Назначение |
|------|------------|
| `config_path` `char[512]` | путь к конфигу (`--config`); пусто = использовать `DEFAULT_CONFIG_PATH` |
| `genconfig_target` `char[512]` | путь для `--genconfig` |
| `keenetic_token` `char[512]` + `keenetic` `int` | токен и флаг режима `--keenetic` |
| `set_mask` `uint32_t` | битовая маска: по одному биту на каждый параметр |
| `overlay` `config_t` | scratch-конфиг, в который CLI-флаги парсятся тем же `param_apply`, что и файл; дублирующего набора полей нет |

### `args_parse(argc, argv, out)`

- `memset(out, 0)` в начале
- `--version`/`-v`: `printf "hrneo vVERSION"`, возвращает 1
- `--help`/`-h`: выводит справку, возвращает 2
- `--config <path>`: парсит путь, продолжает
- `--genconfig [path]`: возвращает 3 (`main → config_generate`)
- `--keenetic <token>`: сохраняет токен, продолжает парсинг (чтобы учесть `--config` в любом порядке), в конце возвращает 4 (`main → config_set_keenetic_token`)
- Для всех остальных флагов — поиск по `PARAMS[]`; неизвестный → `"unknown option"`, `return -1`
- Значение применяется в `out->overlay` через `param_apply(&out->overlay, p, val, 1)`; невалидное → `"invalid value"`, `return -1`
- При успехе `set_mask |= p->set_bit`
- Возвращает `0` (успех), `1` (`--version`), `2` (`--help`), `3` (`--genconfig`), `4` (`--keenetic`), `-1` (ошибка)

### `args_apply(args, cfg)`

- Для каждого `PARAMS[i]` с `set_mask & p->set_bit` — копирует поле из `args->overlay` в `cfg` по `cfg_offset` (один и тот же offset для обоих, т.к. overlay — тоже `config_t`)
- `PT_REPEAT_PATH` / `PT_POLICY_ORDER` заменяют массив полностью (копируются `count` элементов + счётчик)

> Полный список флагов — `docs/HRNEO.CONF.md`.

---

## 12. GeoSite и GeoIP: `src/geodat.c`

### Типы данных

```c
geoip_entry_t    { ip[16], prefix uint32, ip_len uint8 }
geosite_domain_t { type uint32, value char* }
```

### `geosite_domain_t.type`

| Значение | Тип | Поведение |
|----------|-----|-----------|
| `0` | Plain (keyword) | пропускается с `[WARN]` |
| `1` | Regex | пропускается с `[WARN]` |
| `2` | Domain (домен + поддомены) | `ht_insert` с `match_subs=1` |
| `3` | Full | `ht_insert` с `match_subs=1` |

### Парсинг `.dat`-файлов

- Формат: v2ray/xray protobuf, потоковое чтение (`setvbuf 64КБ`)
- `read_varint()` / `read_varint_stream()` для streaming
- `pb_next_field(data, len, &pos, &field)` — единый итератор protobuf-полей (varint / length-delimited, неизвестные wire-type → стоп); все парсеры построены на нём, дублирующейся skip-логики нет
- `scan_dat_file(file, target_upper, visitor, ctx)` — generic stream-сканер (visitor-pattern: `count_geoip_visitor` / `extract_geoip_visitor` / `extract_geosite_visitor`)
- `for_each_geoip_cidr(body, len, fn, ctx)` — обход CIDR-сообщений тега; подсчёт (`count_geoip_entry`) и извлечение (`append_geoip_entry`) — два callback'а одного обходчика
- `extract_geoip_cidrs(file, country)` / `extract_geosite_domains(file, tag)` — полный скан до EOF
- `parse_cidr_body()`, `parse_geosite_body()`, `parse_geosite_domain()` — тонкие switch'и по номеру protobuf-поля поверх `pb_next_field`
- Хелперы: `upcase_inplace`/`upcase_buf` (единственное место ASCII-uppercase), `extract_geoip_country` (разбор `geoip:<tag>`: trim + копия), `cidr_classify` + `copy_block_name` (грамматика строк CIDRfile: BLANK / DISABLED / HEADER / ENTRY — один классификатор для сканера, мигратора и `parse_cidr_policy_headers`)

### `parse_geosite_rules(watchlist_path, rules, max_rules)`

- Читает `domain.conf` через `getline()`, собирает все `geosite:`-записи
- Возвращает `geosite_rule_t[]` (`tag + policy_name`)

### `build_geosite_domain_map(filePaths, fileCount, rules, ruleCount, ht)`

- Для каждого `rule.tag` обходит все `filePaths`, объединяет домены
- `Type=2` (Domain) и `Type=3` (Full): `ht_insert(val, match_subs=1)` — как записи `domain.conf`
- `ht_insert` не перезаписывает существующие → приоритет у `domain.conf`, дубликаты игнорируются

### `parse_cidr_policy_headers(path, names, max_names)`

- Собирает уникальные имена из заголовков `/ИмяПолитики` (классификация строк через `cidr_classify`)
- `##...` и `#/...` строки пропускаются

### `add_cidr_to_ipsets(mgr, cidr_path, geoip_files, geoip_count, maxelem)`

`effective_limit = (maxelem > 0) ? maxelem : IPSET_DEFAULT_MAXELEM (262144)`.

#### Фаза 1 (пресканирование CIDRfile при `geoip_count > 0`)

- `scan_cidrfile_blocks(verbose=0)` + `phase1_on_entry`
- Собирает все уникальные `geoip:TAG` из активных блоков
- Для каждого нового тега → `count_geoip_cidrs_all_files()` → `geoip_tag_count_t` кэш
- `migrate_threshold = effective_limit > CIDR_MIGRATE_HEADROOM ? effective_limit − CIDR_MIGRATE_HEADROOM : 0` (`CIDR_MIGRATE_HEADROOM=5000`)
- **Oversized:** в том же проходе `tag.ipv4 > migrate_threshold || tag.ipv6 > migrate_threshold` → `LOG_WARN`, тег копится в `oversized[]` (детекция совмещена с подсчётом в `phase1_on_entry`, без отдельного цикла)
- После прохода при наличии oversized → `cidrfile_migrate_oversized()` → `LOG_INFO`

#### `cidrfile_migrate_oversized(path, oversized[], count)`

- Читает все строки через `getline()` в динамически растущий массив `cidr_line_t` (старт 4096, ×2 при заполнении), сохраняя `strdup`
- **Pass 1:** присваивает `block_id`, помечает oversized geoip-строки `keep=0`, считает активные записи на блок
- **Pass 2:** блоки без активных записей → заголовок `keep=0`, предшествующие `##` и пустые строки `keep=0`
- Записывает `keep=1` в `.tmp`, дописывает секцию:

  ```
  ##impossible to use
  #/Too-big-geoip-tag
  geoip:<tag>
  ...
  ```

- `rename(.tmp → path)` атомарно

#### Фаза 2 (основная)

- `ipset_refresh_set_list()`
- `scan_cidrfile_blocks(verbose=1)` + `phase2_on_entry`
- Блок активен если `ipset_set_exists()` для ipv4 ИЛИ ipv6 имени
- Oversized теги пропускаются
- Для каждого `geoip:TAG`: cumulative check `usage[v4_target].count + cached_ipv4 > effective_limit` → `LOG_WARN` + `allow_v4=0`; аналогично IPv6
- GeoIP-записи и статические CIDR группируются в `batch_t` по `target_set` (`batch_find_or_add` через open-addressed FNV-1a индекс, `NAME_INDEX_SLOTS=256`)
- Статические CIDR: `usage[target_set].count + 1 > effective_limit` → одно `LOG_WARN` (`warned` флаг), пропуск
- Все батчи отправляются через `ipset_add_batch(with_timeout=0)` → постоянные записи

`usage[]`/`batches[]` адресуются через общий open-addressed FNV-1a индекс `name_index_t` (`NAME_INDEX_SLOTS=256`): один `name_index_lookup` с callback-доступом к имени (`name_at_fn`) обслуживает оба массива — заменяет `O(n)` линейный скан при большом числе целей.

---

## 13. RCI (Remote Configuration Interface) Keenetic: `src/rci.c`

### Архитектурное решение

Штатная работа с роутером Keenetic идёт **исключительно через RCI HTTP/JSON API** на `127.0.0.1:79`. **НЕ используются:** `ndmq`, `curl`, `wget`, `jq`, `python` и любые другие userspace-утилиты роутера. Единственное исключение — `ndmc`, и только как канал бутстрапа токена доступа на прошивках KeeneticOS 5.2+ (см. «Авторизация» ниже); в обычной работе он не вызывается. Весь HTTP-клиент и JSON-парсер — самописные, целиком в `src/rci.c` (455 строк). Это:

- убирает зависимость от наличия и версий системных утилит на роутере
- устраняет `fork`/`exec` на каждое обращение (важно на `SIGUSR1`, где `apply_unified_connmark_rules` может делать до 5 запросов подряд)
- сохраняет совместимость со статической сборкой (никаких `libcurl`/`cJSON` в `LIBS`)
- даёт предсказуемые таймауты через `SO_RCVTIMEO`/`SO_SNDTIMEO`

### Константы (`include/rci.h`)

| Константа | Значение | Назначение |
|-----------|----------|------------|
| `RCI_PORT` | `DEFAULT_API_PORT` (79) | захардкожен, параметра конфига нет |
| `RCI_RAW_MAX` (rci.c) | `32768` | статический приёмный буфер `rci_request` |
| `RCI_TIMEOUT_SEC` | `10` | `SO_RCVTIMEO` и `SO_SNDTIMEO` |
| `RCI_PROBE_PATH` (rci.c) | `/rci/show/version` | проба для определения режима авторизации |
| `RCI_RECOVER_MIN_SEC` (rci.c) | `10` | минимальный интервал между попытками `rci_auth_recover` |
| `NDMC_PATH` (rci.c) | `/bin/ndmc` | канал бутстрапа токена |
| `TOKEN_LABEL` (rci.c) | `HydraRoute` | метка своих токенов; чужие не трогаются |
| `TOKEN_MIN_LEN` / `TOKEN_MAX_OWNED` (rci.c) | `16` / `16` | минимальная длина значения, потолок числа своих токенов при чистке |

### Коды возврата `rci_get_policy_mark` (`include/rci.h`)

| Код | Значение | Смысл |
|-----|----------|-------|
| `RCI_MARK_OK` | `1` | `markID` получен |
| `RCI_MARK_ABSENT` | `0` | политики нет или `markID` ещё не назначен (HTTP 404) |
| `RCI_MARK_TRANSPORT` | `-1` | сетевая ошибка |
| `RCI_MARK_DENIED` | `-2` | 401/403 — авторизация требуется или отклонена |

Разделение `ABSENT` и `DENIED` принципиально: раньше любой не-200 схлопывался в «политики ещё нет», и на прошивке с закрытым loopback правила применялись **без меток политик**, а в лог шло сообщение про нормальную гонку старта.

### Авторизация (KeeneticOS 5.2+)

Режим определяется пробой `RCI_PROBE_PATH` с токеном и без (`rci_resolve_auth`):

| `g_mode` | Условие | Поведение |
|----------|---------|-----------|
| `RCI_MODE_LOCAL` | проба без токена → 200 | заголовок не шлётся |
| `RCI_MODE_TOKEN` | проба с токеном → 200 | `X-NDMA-TKN` на каждом запросе |
| `RCI_MODE_TOKEN_REQUIRED` | авторизация нужна, рабочего токена нет | требуется бутстрап |
| `RCI_MODE_BLOCKED` | токен отклонён и без токена тоже отказ | degraded-режим |

Смена режима логируется один раз (`g_mode_logged`), а не на каждом ретрае.

**`rci_token_bootstrap(config_path)`** — шаг 6a старта, до `create_pid_file`. Если режим `LOCAL` или `TOKEN` — выход `0`, ничего не делается. Иначе `rci_rotate_token`: `ndmc show authentication token` → снятие ANSI-последовательностей (`strip_ansi`) → сбор своих id по метке `HydraRoute` (`ndmc_collect_token_ids`) → удаление своих прежних → `authentication token generate HydraRoute` → значение берётся со следующей строки после `value:` (`ndmc_parse_token_value`) → `config_set_keenetic_token` → `system configuration save`. Затем повторная проба: режим обязан стать `TOKEN`, иначе `LOG_ERROR "Freshly generated RCI token is not accepted by the router"`. Если RCI ещё не отвечает (`g_auth_stale`), проверка откладывается без ошибки.

**`rci_auth_recover(config_path)`** — вызывается из `perform_update()` на каждом коммите. Выходит сразу, если авторизация не помечена сомнительной (`g_auth_stale`, `TOKEN_REQUIRED`, `BLOCKED`); иначе не чаще раза в `RCI_RECOVER_MIN_SEC` = 10 с делегирует в `rci_token_bootstrap`. Токен, отозванный из веб-панели роутера, перевыпускается без рестарта демона.

Значение токена загружается через `rci_set_token()`; недопустимые символы (пробелы, управляющие, не-ASCII) обрезают его при загрузке — защита от инъекции в HTTP-заголовок, факт обрезки пишется в лог.

Клиент не имеет состояния и heap-аллокаций: приёмный буфер — статический 32 КБ в `rci_request` (однопоточный демон), ответы точечных GET — десятки байт. Ранее держались два `malloc`-буфера по ~1 МБ на весь lifetime демона ради разового парсинга полного дерева политик.

### Сетевой клиент

#### `rci_connect()`

- `socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)`
- `SO_RCVTIMEO` / `SO_SNDTIMEO` = 10 секунд (отдельно для send и recv)
- `connect` к `127.0.0.1:79` (`INADDR_LOOPBACK` через `htonl`)
- HTTP/1.0 `Connection: close` (по умолчанию) — каждый запрос = новое TCP-соединение, ответ читается до EOF (закрытия сокета сервером)

#### `rci_request(method, path, body, body_len, response, response_max)`

1. `rci_connect`; при неудаче — `LOG_ERROR` + `return -1`
2. Формирование HTTP-заголовка через `snprintf` (не `fork+printf`):

   ```http
   <METHOD> <PATH> HTTP/1.0
   Host: 127.0.0.1
   Content-Type: application/json     # только при body
   Content-Length: <N>                # только при body

   ```

3. `send` заголовка; при `body` — отдельный `send` цикла `body_len` байт
4. `recv` цикл в статический `raw[RCI_RAW_MAX]` (до 32 КБ − 1 или EOF/0)
5. Парсинг ответа:
   - `strstr("\r\n\r\n")` — граница заголовков и тела
   - `strncmp(raw, "HTTP/", 5)` — sanity-check
   - `strchr(raw, ' ') + atoi` — код статуса; не 200 → `return RCI_HTTP_FAIL (-2)` (транспортная ошибка `-1` различима от HTTP-ошибки: 404 для точечного GET — «политики нет», не сбой сети)
6. `memcpy` тела в `response` (обрезка до `response_max-1`)

### Извлечение `markID`: точечный GET

Вложенные пути работают в RCI **только прямым GET** (в батч-POST под `/rci/` под-атрибуты `show`-команд не поддерживаются — `1179781 not found`, проверено на 5.0.12):

```
GET /rci/show/ip/policy/HydraRoute/mark  →  "ffffaaa"   (HTTP 200, ~10 байт)
GET /rci/show/ip/policy/NoSuch/mark      →  HTTP 404
```

#### `rci_get_policy_mark(name, mark, mark_size)`

1. `rci_request GET /rci/show/ip/policy/<name>/mark`
2. Транспортная ошибка → `-1`; HTTP ≠ 200 → `0` (политики нет или `mark` ещё не назначен)
3. Значение между кавычками, префикс `"0x"`/`"0X"` удаляется (для прямой подстановки в `--set-xmark`), копия в `mark` (усечение до `mark_size-1`)
4. `LOG_DEBUG "RCI policy: %s mark=0x%s"`, возврат `1`

Полное дерево `/rci/show/ip/policy/` (JSON со всеми маршрутами всех политик, растёт с числом маршрутов без ограничений) не выкачивается и не парсится — ручной скобочный парсер и мегабайтные буферы удалены вместе с риском молчаливой поломки на обрезанном ответе.

#### `rci_get_policy_mark(name, mark, mark_size)`

- Без ретраев и без `sleep`: `1` — марк получен, `0` — политика есть, `markID` ещё не назначен, `-1` — транспортная ошибка, `-2` — авторизация отклонена
- Повтор — забота `commit_run()` в `main.c` (фиксированные 3 с, без роста интервала)

### Создание политик

#### `rci_create_policies(names, count)`

1. Формирование тела `POST` вручную — `parse`-команды и `save` **в одном батче** (формат `/rci/` — массив команд, смешанные батчи поддерживаются, проверено на 5.0.12):

   ```json
   [{"parse":"ip policy <name1>"},
    {"parse":"ip policy <name2>"},
    ...,
    {"system":{"configuration":{"save":true}}}]
   ```

   (массив до 8 КБ; ~86 байт на политику, лимит `MAX_POLICY_ORDER=64` помещается с запасом). Команда `parse` эквивалентна вводу строки в CLI Keenetic — `ip policy <name>` создаёт пустую политику если её нет, no-op если есть; `save` сохраняет в startup-config (иначе политики пропадут при перезагрузке роутера).
2. `POST /rci/` с этим body — один запрос вместо прежних двух
3. `LOG_INFO "Policy creation commands executed"`

### Интеграция с остальным кодом

#### `main.c` (порядок старта)

- 14. `rci_create_policies(policy_names, policy_count)` — создание политик для всех целей-политик (интерфейсы DirectRoute сюда не попадают)
- 24. `commit_run()` — первое применение правил

#### `iptables.c::apply_unified_connmark_rules` — вызывается только из `commit_run()`

Шаг 2: по одному `rci_get_policy_mark` на не-interface цель, без ретраев и `sleep`.
Если у политики `mark` пустой (только что создана, роутер ещё не назначил `markID`) —
`LOG_WARN "Policy %s has no mark ID yet"`, цель пропускается в этом батче, функция
возвращает `-1`. Коммитер повторит через фиксированные 3 с, бесконечно. Тем временем
`ipset` продолжает заполняться DNS/L7-каналами, а остальные цели уже промаркированы.

> **Главное правило:** hrneo не молчит при проблемах с RCI, но и не валится — при недоступности роутера демон продолжает работать в degraded-режиме (`ipset` заполняется, конкретные политики временно без CONNMARK-правил).

### Системные требования

- Демон запущен от root (доступ к `loopback:79` + локальная аутентификация NDM, для root прозрачна)
- RCI на роутере включён (на всех современных прошивках Keenetic v3+ — да, по умолчанию)

---

## 14. Netlink Conntrack: `src/conntrack.c`

`conntrack_mgr_t { fd, del_fd, pending[256], pending_count, dump_family, rescan, deleted }` — два long-lived `NETLINK_NETFILTER` сокета (init однократно в `main`, оба закрываются при выходе). `fd` — **неблокирующий** (`SOCK_NONBLOCK`, `SO_RCVBUF` 1МБ), несёт DUMP-поток и зарегистрирован в главном epoll; `del_fd` — DELETE-операции fire-and-forget (без `NLM_F_ACK`). DUMP выполняется асинхронно: однопоточный event loop никогда не блокируется на сканировании таблицы conntrack — это устраняет проигрыш гонки «клиент открыл соединение раньше, чем ipset add» при burst-резолвах (загрузка страницы). Инициализатор в `main.c` — `{ .fd = -1, .del_fd = -1 }`.

### `conntrack_flush_request(m, new_ips, count)` — постановка в очередь

1. Dedup-добавление IP в `pending[]` (по family+ip; переполнение `CT_PENDING_MAX=256` → `LOG_DEBUG`, IP пропускается)
2. Если DUMP уже в полёте (`dump_family != 0`) — только `rescan = 1` (по завершении текущего DUMP будет один повторный проход, т.к. уже пройденные чанки не сверялись с добавленными IP)
3. Иначе — `ct_dump_start()` для первого нужного семейства (IPv4 приоритетнее)

### `conntrack_process(m)` — обработчик EPOLLIN на `m->fd`

1. Цикл `recv(MSG_DONTWAIT)` до `EAGAIN`; `ENOBUFS` (переполнение rcvbuf) → `LOG_DEBUG` и продолжение
2. Для каждой записи чанка: `ct_extract_orig_tuple()` → dst IP → сверка с `pending[]` текущего семейства → `ct_delete_entry(m->del_fd, ...)` при совпадении
3. `NLMSG_DONE`/`NLMSG_ERROR` → `ct_dump_finished()`: переход IPv4→IPv6 (если есть pending IPv6), затем один rescan-проход (если флаг), иначе сброс состояния (`pending_count=0`, `dump_family=0`), счётчик удалений в `LOG_DEBUG`
4. После каждого чанка — `ct_drain_del_fd()`: неблокирующий сброс сообщений об ошибках DELETE (`LOG_DEBUG`)

### `conntrack_delete_conn(m, conn)` — точечный DELETE для L7-канала

Удаляет ровно одну запись по известному 5-tuple `l7_conn_t`, **без DUMP таблицы** (O(1)). Строит `IPCTNL_MSG_CT_DELETE` через `m->del_fd` с собранным вручную `CTA_TUPLE_ORIG`:

- `CTA_TUPLE_IP` (nested): `CTA_IPV4_SRC`/`CTA_IPV6_SRC` = `client_ip`, `CTA_IPV4_DST`/`CTA_IPV6_DST` = `server_ip` (направление original = клиент→сервер, до SNAT — NFLOG-хук стоит на `FORWARD`+`OUTPUT`);
- `CTA_TUPLE_PROTO` (nested): `CTA_PROTO_NUM`=`c->proto` (IPPROTO_TCP для TLS/HTTP, IPPROTO_UDP для QUIC), `CTA_PROTO_SRC_PORT`=`htons(client_port)`, `CTA_PROTO_DST_PORT`=`htons(server_port)`.

Хелперы построения nested-атрибутов: `ct_put_attr` / `ct_nest_begin` / `ct_nest_end` (флаг `NLA_F_NESTED`). Отправка fire-and-forget (без `NLM_F_ACK`), после — `ct_drain_del_fd()` (ошибки в `LOG_DEBUG`, `-ENOENT` игнорируется). Удаление коллатерально не затрагивает другие соединения к тому же IP (в отличие от DUMP-по-dst в DNS-канале).

### Прочие функции

- `ct_extract_orig_tuple()` — ищет `CTA_TUPLE_ORIG` (маска `NLA_TYPE_MASK=0x7FFF`)
- `ct_extract_dst_ip()` — из `CTA_TUPLE_IP` → `CTA_IPV4_DST`/`CTA_IPV6_DST`

---

## 15. Логирование: `src/log.c`

Глобально: `int log_enabled`, `static int log_syslog`, `static FILE *log_fp`. Сборщика статистики (`monitor_stats_t`) нет.

### Уровни логирования (макросы в `include/log.h`)

- `[DEBUG]` / `[INFO]` / `[MATCH]` / `[PROCESSED]` / `[FILTERED]` — выводятся только при `log_enabled=1`
- `[WARN]` / `[ERROR]` — выводятся всегда (не зависят от `log_enabled`); при `log_syslog=1` → `vsyslog(LOG_INFO)` (режимы `syslog` и `off`/иное), иначе → `log_fp` (`stdout` для `console`, файл для `file`). `stderr` остаётся только в вырожденном случае `log=file` с пустым `logfile` (`log_fp=NULL`, syslog не открыт)

### `log_setup(cfg)`

| Значение `log` | Поведение |
|----------------|-----------|
| `console` | `log_fp=stdout`, `log_enabled=1` |
| `file` + `log_file_path[0]!=0` | `mkdir_p` + `fopen(append)`, `log_enabled=1`; пустой путь → `log_enabled=0`, `return 0` |
| `syslog` | `openlog("hrneo", LOG_PID|LOG_NDELAY, LOG_DAEMON)`; `log_syslog=1`, `log_enabled=1` |
| default (`off` и любое другое) | `openlog("hrneo", LOG_PID\|LOG_NDELAY, LOG_DAEMON)`, `log_syslog=1`, `log_fp=NULL`, `log_enabled=0` — отладочные уровни выключены, но `[WARN]`/`[ERROR]` уходят в syslog |

`log_close()`: `fclose()` если `log_fp` не `stdout`/`stderr`; `closelog()` если `log_syslog=1`.

### О счётчиках L7

Диагностических счётчиков в L7-подсистеме нет: прежние `static`-счётчики `l7_dispatch.c`, поля `stat_*`/`count` в `tcp_reasm_t`, `stat_recv`/`stat_err` в `nflog_capture_t` и функция `l7_dispatch_dump_stats()` удалены как мёртвый код (инкрементировались, но никогда не читались и не выводились). Видимая диагностика L7 — события `LOG_MATCH`/`LOG_PROCESSED` с тегами `[TLS-SNI]`/`[HTTP-Host]` и `LOG_WARN` при `ENOBUFS`.

---

## 16. Система сборки: Makefile

**Версия:** 3.18.3-1
**Язык:** C (без CGO, без внешних библиотек)

### Кросс-компиляция

| Цель | Компилятор | Флаги |
|------|------------|-------|
| `mipsel` | `mipsel-linux-muslsf-gcc` | `-march=mips32r2 -mtune=1004kc -EL -msoft-float -mno-check-zero-division -mno-shared -mno-plt`, static `-no-pie` |
| `mips` | `mips-linux-muslsf-gcc` | `-march=mips32r2 -mtune=1004kc -msoft-float -mno-check-zero-division -mno-shared -mno-plt`, static `-no-pie` |
| `aarch64` | `aarch64-linux-musl-gcc` | `-march=armv8-a -mno-outline-atomics -fno-exceptions`, static `-no-pie -Wl,-z,norelro` |
| `native` | `gcc` | dynamic linking |

### Общие флаги

```
-Os -Wall -Wextra -Wno-unused-parameter
-ffunction-sections -fdata-sections
-fno-unwind-tables -fno-asynchronous-unwind-tables
-fomit-frame-pointer
-fno-strict-aliasing
```

**Линковка:** `-Wl,--gc-sections -s`; static: `-static -static-libgcc`. Макрос `VERSION` передаётся через `-DVERSION`.

25 исходных файлов (`src/*.c`), заголовочные в `include/`. Никаких `LIBS`/`LDFLAGS` для L7 — `NFLOG` через стандартный kernel-заголовок `<linux/netfilter/nfnetlink.h>` (формат сообщений `NFULNL_*` задан локально в `nflog_capture.c`). Криптография QUIC (`quic_crypto.c`) — pure-C целочисленная арифметика, MIPS soft-float safe.

### Целевые платформы

- `mipsel-3.4` (linux/mipsle)
- `mips-3.4` (linux/mips)
- `aarch64-3.10` (linux/arm64)

---

## 17. Интеграция с Keenetic (сборка IPK)

- **Init-скрипт:** `/opt/etc/init.d/S99hrneo` — стандартный Entware init (`rc.func`), `ENABLED=yes`, `PROCS=hrneo`, `PIDFILE=/var/run/hrneo.pid`
- **Netfilter hook:** `/opt/etc/ndm/netfilter.d/015-hrneo.sh` — тонкий хук: читает `/var/run/hrneo.pid`; если процесс живёт в `/proc` — `kill -USR1`
- **Symlink:** `/opt/bin/neo` → `/opt/etc/init.d/S99hrneo` (создаётся в `postinst`)
- **postinst:** вставляет `[ $ACTION = start ] && sleep 10` в `rc.unslung` перед запуском, чтобы дать Keenetic поднять интерфейсы (извините, но это решает кучу проблем в т.ч. для другого софта...)
- **UPX:** не применяется ни к одной архитектуре — снижение ложных срабатываний антивирусов (UPX поверх static-stripped ELF — главный триггер эвристик Mirai/Gafgyt).
- **ELF-гигиена:** GNU build-id (`-Wl,--build-id=sha1` в `COMMON_LDFLAGS`) — стабильный идентификатор и note-секция вместо «голого» ELF
- **Зависимости ipk:** `libc`, `ipset`, `iptables`, `ip-full`
- **conffiles:** `/opt/etc/HydraRoute/{hrneo.conf, domain.conf, ip.list}`
- В пакете: минимальный `hrneo.conf` (`log=off`, `logfile=...`, `PolicyOrder=HydraRoute`; остальные ключи возьмут встроенные дефолты), стартовый `domain.conf` (Youtube/Google/Telegram/AI/Other/2ip), `ip.list` с CIDR Telegram

---

## 18. L7-перехват: TLS SNI / HTTP Host / QUIC Initial / TCP-реассамблеция

Второй источник имён хостов параллельно DNS-каналу. По умолчанию **выключен** (`l7CaptureEnabled=false`); включается `l7CaptureEnabled=true`. Закрывает слепые зоны DNS-only схемы: клиенты с DoH/DoT/DoQ, hardcoded-IP TLS, легаси-HTTP, тёплый DNS-кэш устройства, QUIC/HTTP-3.

### 18.1 Цепочки

**TLS/HTTP (TCP):**
```
[Клиент LAN→WAN TCP 443/80]
    → iptables/ip6tables mangle/FORWARD + mangle/OUTPUT -o WAN -p tcp --dport 443|80
      --tcp-flags SYN,ACK ACK -m connbytes 2:N -m length 60: -j NFLOG --nflog-group G
    → nflog_capture (raw NETLINK_NETFILTER, пассивная копия — без verdict)
    → l7_dispatch_packet (fail-fast IP/TCP/dport)
    → probe_tls/probe_http (stateless парсеры) + tcp_reasm (фаза 2)
    → bogon_check → process_hostname_event_l7 → общий путь DNS-канала
      (match_domain_with_cname → ipset_add_batch; полный conntrack-DUMP НЕ вызывается — L7 передаёт allow_conntrack_flush=0)
    → при первом добавлении IP (и ConntrackFlush=true): conntrack_delete_conn(proto=TCP) → точечный DELETE по 5-tuple (реконнект через политику)
```

**QUIC (UDP):**
```
[Клиент LAN→WAN UDP/443, пакет ≥ 1200 байт]
    → iptables/ip6tables mangle/FORWARD + mangle/OUTPUT -o WAN -p udp --dport 443
      -m length --length 1200: -j NFLOG --nflog-group G
    → nflog_capture → l7_dispatch_packet (fail-fast IP/UDP/dport)
    → quic_extract_sni: Long Header detect → версия v1/v2 → Initial-тип
      → DCID → HKDF-Extract(salt, DCID) → client_secret → key/iv/hp
      → header protection removal (AES-128-ECB(hp, sample)) → PN unmask
      → payload decrypt (AES-128-CTR, nonce=iv XOR pn, ctr_start=2)
      → frame walker: PADDING/PING skip, ACK/ACK_ECN full parse (ACK-frame skip)
      → CRYPTO frame: offset==0 и CH целиком в пакете → fake TLS record → tls_extract_sni (fast-path);
        иначе фрагмент (offset, data, len) отдаётся диспетчеру для реассамблеции
    → [фрагментированный ClientHello, MLKEM/Kyber >1 датаграммы]
      dispatch: build_quic_key (5-tuple, family|0x80 — отдельно от TCP) →
      offset==0 → tcp_reasm_start (record_len = 4 + CH body len) / offset>0 → tcp_reasm_feed;
      complete → quic_ch_to_sni(assembled) → tls_extract_sni. Общий пул с TCP-реассамблецией
      (`g_reasm`, GC-таймер 1с, TTL 5с); активна при `l7TcpReasmEnabled=true`
    → bogon_check → process_hostname_event_l7(tag="QUIC-SNI")
    → при первом добавлении IP (и ConntrackFlush=true): conntrack_delete_conn(proto=UDP) → точечный DELETE по 5-tuple UDP
```

`NFLOG` — **нетерминирующая** цель: пакет копируется в netlink-группу и
продолжает обход цепочки. hrneo только читает копию, пакет не трогает и вердикт
не выносит. Поэтому правило hrneo не может «перехватить» трафик у соседних
NFQUEUE-десинхронизаторов (zapret2/nfqws2/tpws) — они работают на той же машине
без конфликта.

Логи различают источник тегом: `[DNS]` / `[TLS-SNI]` / `[HTTP-Host]` / `[QUIC-SNI]`.

### 18.2 Модули

- **`src/probe_tls.c`:** `tls_quick_check` (`d[0]=0x16, d[1]=0x03, d[2]<=0x03, d[5]=0x01`), `tls_extract_sni` (record→handshake→ext→SNI type 0, partial-OK, lowercase).
- **`src/probe_http.c`:** case-insensitive `"\nHost:"`, порт обрезается, IPv6-литерал `[::1]` поддержан.
- **`src/probe_quic.c`:** QUIC CRYPTO-walker для QUIC v1 (RFC 9001) и v2 (RFC 9369). Long Header detect: бит `0xC0`, версия `0x00000001`/`0x6b3343cf`. Initial-тип: `(pkt[0]&0x30)==0x00` (v1) или `==0x10` (v2). HKDF-цепочка: `initial_secret=HKDF-Extract(salt, DCID)` → `client_secret=HKDF-Expand-Label(is, "client in", 32)` → `key`(16B)/`iv`(12B)/`hp`(16B). Header protection: `mask=AES-128-ECB(hp, sample[pn_offset+4:+20])`, first_byte `&=0x0F` (Long Header), PN-байты XOR mask[1..pn_len]. Payload: AES-128-CTR `nonce=iv XOR pn_be` с `ctr_start=2` (GCM-конвенция). Frame walker: PADDING(0x00)/PING(0x01) skip; ACK(0x02)/ACK_ECN(0x03) — полный разбор через `read_varint` (largest_ack, delay, range_count, first_range, alt-ranges, ECN counts) вместо bail — **ключевое отличие от netwatch**; CRYPTO(0x06) — первый найденный фрейм отдаётся наружу через `quic_crypto_frag_t *frag` (`offset`, `data` в статическом `plain[]`, `len`); если `offset==0` и CH целиком в этом фрейме — `quic_ch_to_sni` fast-path (return 1). `quic_ch_to_sni(ch, ch_len, ...)` оборачивает CRYPTO-байты в fake TLS record `0x16 0x03 0x01 len[2]` (len = `ch_len`) → `tls_extract_sni`; используется и fast-path'ом, и после реассамблеции собранного ClientHello. Статические буферы: `plain[2048]`, `rec[QUIC_CH_REC_MAX=8192]` (собранный CH с MLKEM/Kyber крупнее одного датаграма). Реассамблеция многодатаграммного Initial живёт в `l7_dispatch.c` поверх общего `tcp_reasm` — см. ниже.
- **`src/quic_crypto.c`:** SHA-256 (ctx: `state[8]`, `count`, `buf[64]`, `buf_len`; `sha256_compress` с полным schedule), HMAC-SHA256 (ipad/opad через два ctx-прохода), `hkdf_extract` = HMAC-SHA256(salt, IKM), `hkdf_expand_label` (HkdfLabel = `uint16(len)||uint8(6+label_len)||"tls13 "+label||0x00||0x01`). AES-128: 256-байтовый SBOX, 10-байтовый RCON, `aes_key_schedule` (44 слова, 11 round-keys), `aes_encrypt_block` (SubBytes+ShiftRows+MixColumns через `xtime`+AddRoundKey, column-major layout `s[row+4*col]`), `aes128_ecb_encrypt`, `aes128_ctr_xor` (single key schedule, big-endian counter bytes 12-15). Только целочисленные операции — MIPS soft-float safe.
- **`src/bogon.c`:** служебные IPv4 (`0/8, 10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, >=224`) и IPv6 (`ff00::/8, fc00::/7, fe80::/10, ::, ::1, ::ffff:0:0/96`).
- **`src/nflog_capture.c`:** свой NFLOG-клиент без `libnetfilter_log` (subsys `NFLOG_SUBSYS=4` = `NFNL_SUBSYS_ULOG`, `PF_BIND`→`CFG_CMD_BIND`→`CFG_MODE` с `copy_range`+`NLBUFSIZ`, `recv MSG_DONTWAIT`, **без verdict** — поток односторонний). `nflog_capture_t { fd, group, seq, portid, callback, user_data, recv_buf[NFLOG_RECV_BUF_SIZE=128KB] }`. Парсинг атрибута `NFULA_PAYLOAD`. Защита от `ENOBUFS` (`LOG_WARN`, копии теряются — мягкая деградация, трафик клиента не страдает).
- **`src/l7_firewall.c`:** `l7_firewall_resolve_wan` (config + `stat /sys/class/net`, иначе `/proc/net/route Destination==00000000`), `l7_firewall_load_kmod` / `l7_firewall_load_nflog_modules` (`nfnetlink_log`+`xt_NFLOG` через `init_module(2)`, нет `modprobe` на Keenetic), `install/remove` (`fork+exec iptables -w`, `-C ... || -A` для идемпотентности; `-D` в цикле). Правила TCP ставятся в обе цепочки `FORWARD`+`OUTPUT` × `iptables`/`ip6tables`. При `l7_enable_quic` — дополнительно UDP/443 с `--length 1200:` (длина ≥1200 байт — признак QUIC Initial, обязательно padded по RFC 9000). Для `dport 80` `connbytes_max` ужимается до `min(N, 4)`.
- **`src/l7_dispatch.c`:** UDP-ветка (до TCP-проверки): `l4_proto==IPPROTO_UDP`, `dport==443`, `quic_extract_sni(..., &frag)`, `conn.proto=IPPROTO_UDP`. Если fast-path не вернул SNI, но `frag.found` и есть общий реассамблер (`g_reasm_ref`): `build_quic_key` (тот же 5-tuple `tcp_reasm_key_t`, но `family|=0x80` — QUIC-записи не коллидируют с TCP в общем пуле); `frag.offset==0` → `tcp_reasm_start` с `record_len = 4 + (CH body len из frag.data[1..3])`, иначе `tcp_reasm_lookup`+`tcp_reasm_feed(seq=offset)`; на `tcp_reasm_complete` — `tcp_reasm_get` → `quic_ch_to_sni` → `tcp_reasm_destroy`. Незавершённые сборки чистит общий GC (`tcp_reasm_gc`, TTL 5с). При `l7TcpReasmEnabled=false` реассамблеции QUIC нет — только одно-датаграммный fast-path (как и для длинных TLS ClientHello). TCP-ветка: `conn.proto=IPPROTO_TCP` + `try_tls_extract` (fast-path/reasm). `l7_dispatch_set_enable(tls, http, quic)`. `l7_conn_t` (`include/l7_dispatch.h`): поля `family`, `proto`, `client_ip[16]`, `server_ip[16]`, `client_port`, `server_port` — контекст нужен для точечного conntrack-DELETE по 5-tuple с корректным proto.
- **`src/tcp_reasm.c`** (фаза 2): 5-tuple хеш (`TCP_REASM_BUCKETS=64`), пул `calloc-on-init` (`l7TcpReasmMaxEntries × TCP_REASM_BUF_SIZE=16KB`), `start/feed/complete/get/destroy/gc`, seq-упорядочивание (gap→drop, retransmit→no-op), LRU-eviction (`evict_lru` возвращает освобождённый слот — без повторного скана пула), `timerfd` GC (TTL `l7TcpReasmTtlSec`). Общий для двух источников: TCP-сегменты (`seq`) и QUIC CRYPTO-фрагменты (`seq`=CRYPTO offset, `record_len`=4+CH body len); QUIC-ключи помечены `family|0x80`, поэтому не коллидируют с TCP-записями в одном пуле. Оба потока байт — уже раскодированный prefix ClientHello, семантика хранилища для них одинакова.

### 18.3 Архитектурные решения

- Вся системная логика в C-демоне; shell-хук `015-hrneo.sh` «тонкий» (только `kill -USR1`). Нет «зомби-скриптов» при остановленном демоне. `S99hrneo` минимальный.
- Один NFLOG-сокет; диспетчер разводит по `dport`.
- **NFLOG вместо NFQUEUE:** L7 только читает SNI/Host, пакет не модифицирует — назначение NFLOG, а не NFQUEUE. Нетерминирующая цель устраняет конкуренцию за трафик с zapret2/nfqws2. Нет verdict-сообщений → нагрузка ниже, чем у прежней NFQUEUE-схемы. Без fallback: нет модулей NFLOG → L7 выключается (`LOG_WARN`), демон работает на DNS-канале.
- **Хуки FORWARD+OUTPUT, не POSTROUTING:** `FORWARD` покрывает forwarded LAN→WAN (после routing-decision доступен `-o WAN`), `OUTPUT` — соединения самого роутера. Ранний по ходу пакета хук даёт чистый ClientHello до десинхронизации соседнего NFQUEUE-демона.
- Идемпотентность к DNS: `ipset_add_batch` с `NLM_F_EXCL` → двойное добавление IP no-op. Два источника (DNS + L7) безопасно пересекаются.
- **Conntrack-реконнект L7 (`conntrack_delete_conn`):** L7 видит SNI/Host уже после установления TCP-соединения, выпущенного через WAN (до попадания dst-IP в ipset). Чтобы соединение пошло по политике, hrneo при **первом** добавлении IP (`process_hostname_event` вернул `> 0`, т.е. `NLM_F_EXCL`-новый) и при `ConntrackFlush=true` точечно удаляет conntrack-запись этого соединения по полному 5-tuple. Следующий пакет переоценивает `CONNMARK`-правила, смена src/NAT через политику вынуждает легитимный реконнект. Ранее здесь использовалась инъекция spoof-RST клиенту (`l7_rst.c`, удалён): RST как in-band-пакет обязан совпасть с `rcv_nxt` (RFC 5961, strict) и проигрывал гонку с ответом сервера — на практике соединение не рвалось и шло мимо политики. conntrack-DELETE действует на состоянии ядра, проверки seq-окна нет → надёжно. Удаляется только триггернувшее соединение (точно по 5-tuple, без коллатерали); полный conntrack-DUMP из L7 не вызывается — это прерогатива DNS-канала.
- **GRO coalescing:** на роутере с GRO ядро склеивает TCP-сегменты до netfilter → NFLOG копирует CH целиком даже Kyber-размера → fast-path. Реассамблеция фазы 2 — страховочная сетка (GRO off / разные CPU / MSS-clamp / PMTU-дробление).

### 18.4 Известные gaps (НЕ реализовано)

- **QUIC v2 Initial type detection** — версия v2 определяется по `version==0x6b3343cf`; реализована. Многодатаграммный Initial (MLKEM/Kyber ClientHello, разбитый на 2+ Initial-пакета) реассамблируется по CRYPTO-offset — реализовано (§18.2, `l7_dispatch.c`). Не реализовано: Retry-пакеты (DCID меняется на Retry Token), несколько CRYPTO-фреймов внутри одного датаграма (берётся первый — на практике клиент кладёт по одному CRYPTO на Initial), QUIC over IPv6 Extension Headers с нестандартным next_header.
- **ECH (Encrypted ClientHello)** — нерешаемо без MITM
- **iCloud Private Relay** — зашифрованный туннель, SNI релея (by design не наш)

---

## 19. Реализованные оптимизации

> Бо́льшая часть сведений потеряна т.к. не документировалась.

- **Однопоточная event-driven архитектура.** epoll-цикл: `cap.fd4` + `cap.fd6` + `signals.sig_fd` + `signals.timer_fd` + (опц.) `g_conntrack.fd` + `nflog_fd` + `reasm_gc_fd`. Без GC, без потоков, без каналов.
- **Netlink вместо `fork`/`exec` для ipset.** Все `CREATE`, `FLUSH`, `ADD` через прямой netlink-сокет (`NETLINK_NETFILTER`, long-lived).
- **Батчевая отправка ipset через netlink.** `ipset_add_batch()`: чанки по 256 — send N сообщений, затем recv N ответов. Kernel обрабатывает очередь параллельно с чтением ответов.
- **`iptables-restore` для batch-правил.** `apply_unified_connmark_rules()`: все `CONNMARK`-правила одним вызовом `iptables-restore --noflush`.
- **Хеш-таблица доменов с chunked pool.** 8192 бакетов, FNV-1a, цепочки. Chunked pool 256КБ с автоматическим расширением — ноды и строки в одном аллокаторе. Дедупликация `ipset_name` через `ipset_name_cache[]`.
- **Суффиксный матчинг через хеш-таблицу.** Для каждой точки в домене проверяется parent-домен — `O(количество точек)`, каждая `O(1)` средний.
- **Кэш ipset-списков и единый timeout.** `set_names[]` (cache `ipset list -n` при старте) + одно поле `default_timeout` менеджера (timeout одинаков для всех сетов) — в `ipset_add_batch` нет ни хеширования имени, ни риска коллизий.
- **Общий open-addressed FNV-1a индекс.** `name_index_t` в `geodat` для `batches[]` и `usage[]` (`NAME_INDEX_SLOTS=256`, доступ к имени через `name_at_fn`) — заменяет `O(n)` линейный поиск при большом числе целей.
- **Коалесцирование SIGUSR1.** Один `timerfd` на leading-edge цикл: первый сигнал пишет таблицу немедленно, пока цикл активен — сигналы игнорируются целиком, без сброса таймера. Пачка из ~30 хуков одного `interface X down` даёт ровно две записи вместо тридцати.
- **Асинхронный conntrack flush через netlink.** Два long-lived netlink-сокета (init однократно): неблокирующий `fd` для DUMP-потока (в epoll, чанки читаются между DNS-пакетами) + `del_fd` для DELETE fire-and-forget (без `NLM_F_ACK`). Новые IP коалесцируются в pending-буфер — один DUMP на burst вместо DUMP на каждый DNS-ответ, event loop не блокируется на сканировании таблицы. Без `fork`/`exec`.
- **Стриминговый парсинг .dat-файлов.** Потоковое чтение через `setvbuf(64KB)`. В памяти хранятся только извлечённые записи. Visitor-pattern (`scan_dat_file`).
- **Статическая аллокация в hot path.** `dns_result_t` (static в `process_dns_packet`), `processed[]`, `ipv4_batch[]`, `ipv6_batch[]`, `all_new[]` — на стеке, без `malloc`. CNAME-записи передаются в матчер как `dns_cname_t` напрямую из результата парсинга — промежуточного копирования на каждый DNS-ответ нет.
- **Unified targets.** `g_all_sorted[]` объединяет политики и интерфейсы в единый отсортированный массив. `apply_unified_connmark_rules()` обрабатывает все цели одним проходом.
- **Дедупликация указателей `ipset_name`.** `ht_insert()` ищет существующий указатель через `ipset_name_cache[]` перед аллокацией нового.
- **AF_PACKET SOCK_DGRAM + L3-BPF в ядре.** BPF-фильтры на сокетах через `SO_ATTACH_FILTER`. Ядро отбрасывает нерелевантные пакеты до копирования в userspace — только DNS-ответы достигают `process_dns_packet`. `SOCK_DGRAM` отдаёт пакет с IP-уровня единообразно для всех типов интерфейсов, поэтому фильтр работает по IP-версии/протоколу/порту без привязки к Ethernet-кадру.
- **Контроль maxelem.** Единый проход подсчёта geoip-записей (счётный callback `for_each_geoip_cidr`, без аллокаций) с совмещённой детекцией oversized: тег с числом записей больше `IpsetMaxElem − CIDR_MIGRATE_HEADROOM (5000)` мигрирует в disabled-секцию `CIDRfile` (атомарно через `.tmp + rename`); при загрузке суммарный размер каждого ipset ограничивается `IpsetMaxElem` с переиспользованием тех же подсчётов.
- **Table-driven config.** `PARAMS[]` (`src/params.c`) — одно описание параметра обслуживает `config_read`, `args_parse`/`args_apply`, `print_help`, `config_generate`.
- **L7 fail-fast каскад.** Длина → IP-версия → TCP → флаги → dport → 1-байтовая сигнатура TLS/HTTP → парсер. Реассамблеция запускается только для фрагментированных CH (fast-path для коротких). Один NFLOG-сокет.

---

## Резюме

**HRNeo v3.18.3-1** — компактный однопоточный policy routing демон для роутеров Keenetic, написанный на чистом C.

Два источника имён хостов:

- **DNS-канал** — перехват DNS-ответов через AF_PACKET SOCK_DGRAM + L3-BPF, два fd; работает на интерфейсах любого типа (Ethernet, PPP, ARPHRD_NONE, туннели), поэтому ловит DNS LAN- и VPN-клиентов одним кодом
- **L7-канал** — TLS SNI / HTTP Host / QUIC Initial SNI исходящих соединений через собственный NFLOG-клиент на raw netlink (пассивное копирование, совместимо с zapret2/nfqws2), при `l7CaptureEnabled`; фаза 2 — реассамблеция фрагментированных ClientHello: TCP-сегменты и QUIC CRYPTO-фрагменты многодатаграммного Initial (общий пул `tcp_reasm`); QUIC: CRYPTO-walker с полной HKDF + AES-128-CTR дешифровкой Initial-пакета; при первом добавлении IP (и `ConntrackFlush=true`) триггернувшее соединение разрывается точечным удалением conntrack-записи по 5-tuple (TCP или UDP) для мгновенного реконнекта через политику

Извлекает IP-адреса и добавляет в `ipset` через netlink, маркирует трафик в `iptables/mangle` для policy routing. Поддерживает маршрутизацию через политики Keenetic (mark через RCI API) и прямую на интерфейсы (`fwmark` + `ip rule` + `ip route`). GeoIP/GeoSite из `.dat` v2ray/xray с потоковым protobuf-парсингом.

Event-driven архитектура на `epoll` (`cap.fd4` + `cap.fd6` + `signalfd` + `timerfd` + `g_conntrack.fd` + `nflog_fd` + `reasm_gc_fd`).

**29 параметров конфига**, все доступны через CLI-флаги (`--flag value`) + `--config <path>`, `--version`/`-v`, `--help`/`-h`, `--genconfig [path]`, `--keenetic <token>`; приоритет: CLI > конфиг > дефолты. Описание параметров — единая таблица `PARAMS[]` в `src/params.c`, драйвит `config_read`, args, `--help`, `--genconfig`.

**Оптимизирован:** батчевый netlink (send N / recv N), хеш-таблица доменов 8192 бакетов с chunked pool (256КБ чанки), unified targets, batch `iptables-restore`, коалесцирование сигналов netfilter, conntrack flush через netlink с long-lived сокетом, статическая аллокация в hot path, двунаправленный CNAME BFS, BPF-фильтрация в ядре, `ipset CREATE` с автоматическим запросом kernel-revision, контроль `maxelem` с автомиграцией oversized `geoip:TAG` в disabled-секцию `CIDRfile`.
