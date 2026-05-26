# HRNeo — техническая документация кодовой базы

Исходный код HRNeo (HydraRoute Neo) v3.11.0-1: архитектура, модули, потоки данных, оптимизации.

---

## 1. Общая архитектура и принцип работы

HRNeo — демон для policy routing на роутерах Keenetic (Entware). Чистый C (без CGO, без внешних библиотек кроме libc и Linux API), единый статически скомпилированный бинарник. Версия 3.11.0-1.

### Два независимых источника имён хостов

- **DNS-канал** (всегда): перехват DNS-ответов dnsmasq через AF_PACKET SOCK_DGRAM + L3-BPF. Работает на интерфейсах любого типа — Ethernet, PPP, ARPHRD_NONE (WireGuard, VPN-сервер, IPsec, туннели). Ловит DNS и LAN-, и VPN-клиентов.
- **L7-канал** (опционально, `l7CaptureEnabled`): перехват TLS SNI / HTTP Host исходящих соединений через NFQUEUE. Фаза 2 — TCP-реассамблеция длинных ClientHello. Подробно — раздел [18](#18-l7-перехват-tls-sni--http-host--tcp-реассамблеция).

### Принцип работы (пошагово)

1. Читается конфигурация из `/opt/etc/HydraRoute/hrneo.conf` (27 параметров; CLI-флаги поверх конфига; недостающие — встроенные дефолты).

2. Если `DirectRouteEnabled=true` — сканируется `/sys/class/net/`, строится карта системных интерфейсов (`drm_scan_interfaces`): для каждого имени читается `/sys/class/net/<name>/operstate` (`up`/`down`/`unknown`). Карта нужна, чтобы при разборе watchlist различать «политика Keenetic» и «сетевой интерфейс для DirectRoute».

3. Парсится watchlist (`domain.conf`). Каждая строка имеет формат `домен1,домен2,geosite:TAG/Цель`. Цель классифицируется через `drm_classify_target` по карте интерфейсов из шага 2:
   - имя совпало с интерфейсом → цель является интерфейсом (DirectRoute, маршрутизация будет через `ip rule + ip route`)
   - не совпало → цель является политикой Keenetic (маршрутизация будет через политику роутера с её mark)

   Результат: разделённые массивы `policy_names[]` и `iface_names[]`. Лог: `[INFO] domain.conf: %d policies, %d interfaces`.

4. Опционально (`CIDR=true`): из `CIDRfile` (`ip.list`) извлекаются уникальные заголовки `/Name` через `parse_cidr_policy_headers`. Имена-интерфейсы фильтруются через `drm_classify_target`, остальные добавляются в список политик. Лог на каждое новое имя: `[INFO] CIDR: added policy 'X'`.

5. Опционально (есть `GeoSiteFile`): `parse_geosite_rules` собирает `geosite:TAG/Цель` из watchlist'а; имена-цели добавляются в политики (опять же intf-цели отфильтровываются). Лог: `[INFO] GeoSite: added policy 'X'`.

6. Применяется `PolicyOrder` через `sort_policies` (см. раздел [5](#5-матчинг-доменов-srcwatchlistc)). Сортировка делается дважды: для одних только политик (для шага 7) и для объединённого массива policy + iface (для шага 9). Итог печатается:

   ```
   [INFO] Target order (N):
     [0] HydraRoute (policy)
     [1] nwg0 (interface, fwmark=0x3001)
     ...
   ```

7. **Создание/проверка политик Keenetic через RCI** (`rci_create_policies`): hrneo формирует `POST /rci/ HTTP/1.0` с JSON-массивом `[{"parse":"ip policy <name1>"}, {"parse":"ip policy <name2>"}, ...]` и отправляет на `127.0.0.1:79`. Команда `parse` эквивалентна вводу `ip policy <name>` в CLI Keenetic — существующие политики не трогает, отсутствующие создаются пустыми (без VPN-интерфейсов; их администратор присвоит через веб-интерфейс роутера Keenetic). После — безусловный `POST /rci/ {"system":{"configuration":{"save":true}}}` (сохранение в startup-config). Интерфейсы из `iface_names[]` в RCI не отправляются — для них политики Keenetic не нужны. Лог: `[INFO] Policy creation commands executed`. Подробнее — раздел [13](#13-rci-remote-configuration-interface-keenetic-srcrcic).

8. Создаются `ipset`-множества `hash:net` (IPv4 и IPv6 отдельно) для каждой цели (политика или интерфейс): по два сета на target — `<name>` (IPv4) и `<name>v6` (IPv6). Через netlink с `NLM_F_CREATE|NLM_F_EXCL`; существующие сеты не пересоздаются. Кэшируется `ipset_timeout`. При `clearIPSet=true` — `FLUSH` каждого сета.

9. Опционально (`CIDR=true`): загрузка статических CIDR-блоков в `ipset` (`add_cidr_to_ipsets`). Двухфазная обработка: фаза 1 — пресканирование `geoip:TAG` и автомиграция oversized тегов в disabled-секцию; фаза 2 — собственно `ipset_add_batch` для активных блоков.

10. Опционально (есть `GeoSiteFile`): `build_geosite_domain_map` загружает домены типов `Domain`/`Full` из `.dat`-файлов в хеш-таблицу с приоритетом у `domain.conf` (`ht_insert` НЕ перезаписывает существующие).

11. Если `DirectRoute=true` — `drm_setup_all_routes`:

    ```
    ip [-6] rule add priority N fwmark 0x<mark> table <T>
    ip [-6] route add default dev <iface> table <T>   # или blackhole
    ```

    `fwmark` и `table_id` уникальные, выделяются последовательно от `InterfaceFwMarkStart` (12289) и `InterfaceTableStart` (301).

12. **Извлечение `markID` политик через RCI** + создание `CONNMARK`-правил `iptables` (`apply_unified_connmark_rules`):
    - `GET /rci/show/ip/policy/` возвращает JSON `{"<Name>":{"mark":"0xNN", ...}, ...}`
    - hrneo вручную парсит ответ (`find_matching_brace` + `strstr "mark"`), извлекает hex-значение `markID` для каждой политики, снимает префикс `0x`. Лог при `log=console/file`: `[DEBUG] RCI policy: HydraRoute mark=0x21`
    - Двухуровневая retry-защита: `rci_get_policies_with_retry` (до 5 попыток × 3с) от сетевых ошибок; внутренний loop (до 5 попыток × 4с) от свежесозданных политик без `markID` (роутер назначает его не сразу после `parse`)
    - Для целей-интерфейсов `markID` не запрашивается — используется назначенный `fwmark`
    - Для каждой цели в порядке `g_all_sorted[]` формируется пара `CONNMARK`-правил в `mangle/PREROUTING`, через `iptables-restore --noflush` (один вызов на весь батч). Если у политики `mark` пустой после retry — `LOG_WARN "Policy %s has no mark ID, skipping"`, цель пропускается (`ipset` продолжит заполняться, но трафик не маркируется)

13. Инициализируется `AF_PACKET` захват DNS-ответов: два `SOCK_DGRAM/ETH_P_ALL` сокета с L3-BPF (`fd4` для IPv4, `fd6` для IPv6).

14. Опционально (`l7CaptureEnabled=true`): резолв WAN (config или `/proc/net/route`), `init_module(xt_connbytes)`, `nfq_capture_init`, `NFQUEUE`-правила `iptables`/`ip6tables` для TCP 443/80; при `l7TcpReasmEnabled` — `tcp_reasm_init` + `timerfd` GC (1с).

15. Основной epoll-цикл перехватывает DNS-ответы (`AF_PACKET`) и L7-пакеты (`NFQUEUE`), добавляет IP в `ipset` через netlink.

16. Если `ConntrackFlush=true` И IP добавлен в `ipset` впервые (`NLM_F_EXCL` вернул `err==0`, а не `IPSET_ERR_EXIST`), для каждого такого IP делается `conntrack`-DUMP с DELETE по совпадению dst-IP. Реальное удаление происходит только при наличии активной `conntrack`-записи к этому IP; если соединения к IP ещё нет — DUMP проходит вхолостую, DELETE не отправляется.

17. Обрабатываются сигналы:
    - `SIGUSR1` — обновление состояния интерфейсов + пересоздание `CONNMARK`-правил (включая повторный `GET /rci/show/ip/policy/` для возможно изменившихся `markID`) + реинсталл L7-правил (idempotent через `iptables -C`). Debounce 5с через `timerfd`
    - `SIGINT`/`SIGTERM` — штатная остановка: снятие L7 `NFQUEUE`-правил, удаление `CONNMARK`, удаление `ip rule` + flush таблиц DirectRoute, закрытие netlink-сокетов, удаление PID-файла

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
[netlink: удаление conntrack-записей для новых IP (DUMP + DELETE if present)]

[Исходящий трафик клиента]
   → iptables/mangle PREROUTING
   → CONNMARK set-xmark по ipset dst match
   → CONNMARK restore-mark
   → ip rule fwmark → table X → ip route default dev <interface>
```

### Файловая структура (23 файла `.c`)

| Файл | Назначение |
|------|------------|
| `src/main.c` | Точка входа, event loop (epoll), обработка DNS |
| `src/packet_capture.c` | AF_PACKET SOCK_DGRAM захват DNS (L3-BPF) |
| `src/iptables.c` | CONNMARK-правила, unified targets |
| `src/routing.c` | DirectRoute: ip rule, ip route, интерфейсы |
| `src/watchlist.c` | Парсинг domain.conf, матчинг доменов |
| `src/config.c` | Парсинг hrneo.conf + config_generate |
| `src/args.c` | Парсинг CLI, наложение на config |
| `src/params.c` | PARAMS[] — таблица описания параметров (single source of truth для config/args/help/genconfig) |
| `src/ipset_nl.c` | Низкоуровневая работа с ipset через netlink |
| `src/conntrack.c` | Сброс conntrack-записей через netlink |
| `src/dns.c` | Парсинг DNS-ответов (A, AAAA, CNAME) |
| `src/log.c` | Логирование (console/file/syslog/off) |
| `src/util.c` | Хеш-таблица доменов, chunked pool, fork/exec |
| `src/rci.c` | HTTP/JSON взаимодействие с API Keenetic |
| `src/signal_handler.c` | `signal_mgr_t` (signalfd + timerfd manager) |
| `src/geodat.c` | Парсинг GeoIP/GeoSite .dat файлов (protobuf) |
| `src/probe_tls.c` | Stateless парсер TLS ClientHello → SNI |
| `src/probe_http.c` | Stateless парсер HTTP request → Host |
| `src/bogon.c` | Фильтр служебных IPv4/IPv6 диапазонов |
| `src/nfq_capture.c` | NFQUEUE через raw NETLINK_NETFILTER (без libnfq) |
| `src/l7_dispatch.c` | Fail-fast диспетчер пакетов → probe → reasm |
| `src/l7_firewall.c` | WAN-резолв, init_module, iptables NFQUEUE-правила |
| `src/tcp_reasm.c` | 5-tuple TCP-реассамблеция длинных ClientHello |
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
| `MANGLE_TABLE` | `"mangle"` | таблица iptables |
| `SOCKET_READ_BUFFER` | 1 МБ | `SO_RCVBUF` для AF_PACKET |
| `SIGUSR1_DEBOUNCE_SEC` | `5` | debounce SIGUSR1 |
| `RCI_TIMEOUT_SEC` | `10` | таймаут RCI-запроса |
| `POLICY_API_MAX_RETRIES` | `5` | попыток на `GET /rci/show/ip/policy/` |
| `POLICY_API_RETRY_DELAY` | `3` | секунды между попытками |
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

### `config_t` (27 полей)

См. `src/params.c` и `docs/HRNEO.CONF.md`. Поля:

`auto_start`, `watchlist_path`, `clear_ipset`, `cidr_enabled`, `cidr_file_path`, `ipset_enable_timeout`, `ipset_timeout`, `log_level`, `log_file_path`, `direct_route_enabled` (default 1), `interface_fwmark_start` (12289), `interface_table_start` (301), `global_routing`, `conntrack_flush` (1), `ipset_maxelem` (262144), `geo_ip_files[16][512]`+counter, `geo_site_files[16][512]`+counter, `policy_order[64][64]`+counter, `l7_capture_enabled` (1), `l7_queue_num` (210), `l7_enable_tls` (1), `l7_enable_http` (1), `l7_connbytes_max` (8), `l7_wan_interface[32]`, `l7_tcp_reasm_enabled` (1), `l7_tcp_reasm_max_entries` (256), `l7_tcp_reasm_ttl_sec` (5).

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
conntrack_mgr_t         g_conntrack = { .fd = -1 };
rci_client_t            g_rci;
nfq_capture_t           g_nfq;
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
   - ошибка: `return -1 → 1`
2. `sigprocmask(SIG_BLOCK)` для `SIGINT`/`SIGTERM`/`SIGUSR1`
3. `config_read()` — путь из `args.config_path` или `DEFAULT_CONFIG_PATH`; явный `--config` при недоступном файле → выход 1
4. `args_apply()` — наложение CLI-флагов (только `set_mask`-биты)
5. Если `!auto_start` → `return 0`
6. `log_setup()` + `LOG_INFO "HRNeo v%s starting"` + `create_pid_file()`
7. `ht_create()` — создание хеш-таблицы доменов
8. Если DirectRoute: `drm_init()`, `drm_scan_interfaces()`, `parse_watchlist_classified()` → для каждого iface: `drm_allocate_fwmark()`, `drm_allocate_table_id()`, `drm_register_route()`. Иначе: `parse_watchlist()`, `get_unique_names()`
9. `CIDR=true`: `parse_cidr_policy_headers()` — добавляет политики из заголовков `/Name` CIDR-файла; intf-цели отфильтровываются через `drm_classify_target`; `LOG_INFO "CIDR: added policy 'X'"` для каждой новой
10. GeoSite файлы заданы: `parse_geosite_rules()` — добавляет политики из `geosite:`-правил watchlist; intf-цели отфильтровываются; `LOG_INFO "GeoSite: added policy 'X'"` для каждой новой
11. `sort_policies()` для `policy_names` с учётом `PolicyOrder`
12. `g_all_sorted[]`: `all_names = policy_names + iface_names`, `sort_policies()` на объединении; `unified_target_t = {pair (ipv4/ipv6 имена), is_interface, fwmark}`
13. `LOG_INFO "Target order (%d):"` — вывод порядка целей
14. `rci_client_init(&g_rci)` — выделение `raw_buf` + `response_buf` (~1 МБ + 1 МБ)
15. `rci_create_policies()` — только для `policy_names` (POST + save)
16. `ipset_manager_init()` + `initialize_ipsets()` — создание/очистка ipset-пар для всех `g_all_sorted`, кэширование `timeout`
17. `add_cidr_to_ipsets()` — если `CIDR=true` и `cidr_file_path` задан
18. `build_geosite_domain_map()` — если `geo_site_file_count > 0`
19. `drm_setup_all_routes()` — `ip rule` + `ip route` для DirectRoute
20. `apply_unified_connmark_rules()`
21. Если `conntrack_flush` — `conntrack_mgr_init()` (при ошибке flush отключается)
22. `pkt_capture_init()` — два `AF_PACKET SOCK_DGRAM/ETH_P_ALL` сокета (`fd4`, `fd6`)
23. Если `l7_capture_enabled`: `l7_firewall_resolve_wan`; при неудаче — L7 отключается с `LOG_WARN`. Иначе: `l7_firewall_load_kmod("xt_connbytes")` через `init_module(2)`; `l7_dispatch_set_enable`; при `l7_tcp_reasm_enabled` — `tcp_reasm_init` + `l7_dispatch_set_reasm` (`g_reasm_active=1`); `nfq_capture_init`; `l7_firewall_install` (NFQUEUE для TCP 443/80). `g_l7_active=1` при успехе
24. `signal_mgr_init()` — `sigprocmask` + `signalfd` + `timerfd`
25. `epoll_create1()` — регистрация `cap.fd4`, `cap.fd6`, `signals.sig_fd`, `signals.timer_fd`; при `g_l7_active` — `nfq_fd`; при `g_reasm_active` — `reasm_gc_fd` (`timerfd` 1s)
26. Основной цикл `epoll_wait` (`events[8]`)
27. **Cleanup:** `signal_mgr_close` → `l7_firewall_remove` + `nfq_capture_close` → `tcp_reasm_close` (если `g_reasm_active`) → `pkt_capture_close` → `conntrack_mgr_close` → `drm_cleanup_all_routes` → `cleanup_connmark_rules` → `ipset_manager_close` → `rci_client_close` → `ht_destroy` → `remove_pid_file` → `log_close`

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
2. Сборка `cname_entry_t[]` (`from`/`to`) из `result.cnames[].source/target` (статический массив)
3. Итерирует уникальные домены (`processed[64][256]` на стеке) — для каждого:
   - Сбор IPv4/IPv6 батчей из `answers` (до 32 каждого семейства)
   - `process_hostname_event(domain, cnames, ..., "DNS")` — общий хелпер с L7-каналом

### `process_hostname_event(domain, cnames, ipv4_batch, ipv4_count, ipv6_batch, ipv6_count, source_tag)`

1. `match_domain_with_cname` → `ipset_name` (или `NULL` — пропуск)
2. `LOG_MATCH "[<tag>] <domain> -> <ipset>"` (или `"<domain> via <matched_domain> -> <ipset>"` при CNAME)
3. `ipset_add_batch` для IPv4 (`setname`, `with_timeout=1`)
4. `ipset_add_batch` для IPv6 (`setname + "v6"`, `with_timeout=1`)
5. `LOG_PROCESSED` для каждого реально добавленного (нового) IP
6. `conntrack_flush_for_ips()` если `conntrack_flush=1` и есть новые IP (для каждого нового IP DUMP+DELETE по dst; DELETE отправляется только при существующих conntrack-записях к этому IP, иначе DUMP вхолостую)

### `process_hostname_event_l7(host, proto, daddr, family)`

Обёртка из L7-канала (вызывается из `l7_dispatch.c`): заполняет `parsed_cidr_t` из `daddr` и вызывает `process_hostname_event` с тегом `"TLS-SNI"` / `"HTTP-Host"`.

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

### `parse_cidr_policy_headers(path, names, max_names)`

- Читает CIDR-файл через `getline()`, собирает уникальные имена из активных заголовков `/ИмяПолитики`
- Пропускает `##...` и `#/...` строки

### `sort_policies(names, count, order, order_count)`

- `order` пустой → `qsort` алфавитно
- иначе: сначала элементы из `order` (по порядку), затем остальные алфавитно
- Элементы `order`, отсутствующие в `names` → `LOG_WARN`

### PolicyOrder — единственный механизм приоритезации целей

Работает на **ДВУХ уровнях независимо**:

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
| `set_has_timeout[256]` | кэш timeout-режима (индекс: `FNV-1a & 0xFF`) |
| `timeout_value[256]` | кэш значений timeout |
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

1. Читает кэш `timeout` через FNV-1a индекс
2. Фильтрует service IP через `is_service_ip()` (`LOG_FILTERED`)
3. Формирует netlink-сообщения через `build_ipset_add_msg()` с `TIMEOUT`-атрибутом, когда кэш `has_timeout=1` и `with_timeout=true`
4. Чанки по `IPSET_CHUNK_SIZE=256`: send все сообщения чанка, затем recv все ответы
5. `with_timeout=true`: `NLM_F_EXCL` (повторное добавление → `IPSET_ERR_EXIST` без обновления `timeout`); `new_indices` заполняется только при `with_timeout=true`
6. `with_timeout=false`: `NLM_F_CREATE` без `NLM_F_EXCL`; `new_indices` не заполняется
7. Обработка ошибок netlink ack:
   - `err->error == 0` → запись добавлена, индекс пишется в `new_indices` при `with_timeout=1`
   - `IPSET_ERR_HASH_FULL` (4101) → `LOG_WARN "ipset '%s' full"`
   - `IPSET_ERR_EXIST` (4103) → молча игнорируется
   - Прочие коды → `LOG_DEBUG "Netlink ADD error: errno=%d"`

### Прочие функции

- `ipset_cache_timeout_for_set()` — записывает `timeout` в кэш по индексу `FNV-1a & 0xFF`
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

1. `get_br0_networks()`: `ip addr show br0` — получает IPv4-сеть (обязательно) и IPv6-сеть `scope global`
2. Внутренний retry loop (до 5 попыток, sleep 4s): `rci_get_policies_with_retry()` + проверка наличия `mark` для каждой не-interface цели. Если хотя бы одна политика без `mark` — повтор через 4 секунды
3. Получает текущие правила через `iptables/ip6tables -w -t mangle -S PREROUTING`
4. Для каждого `unified_target`:
   - **Интерфейс:** `mark = fwmark` (hex)
   - **Политика:** `mark` из RCI-ответа; если `mark` пуст — цель пропускается с `[WARN]`
5. `find_mark_in_rules()` — проверяет существующий `mark` в кэшированных правилах
6. Если правила нет или `mark` изменился — удаляет старые, добавляет в batch
7. IPv4 batch → `iptables-restore --noflush`
8. IPv6 batch → `ip6tables-restore --noflush`, но только если `is_interface=true` или `br0` имеет IPv6-адрес

#### Правила CONNMARK (`GlobalRouting=false`)

```
-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0
   -m connmark --mark 0x0/0xffff0000
   -m set --match-set <ipset> dst
   -j CONNMARK --set-xmark 0x<mark>/0xffffffff

-A PREROUTING -m set --match-set <ipset> dst
   -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
```

`GlobalRouting=true`: условие `! --mark 0xffffaa0/0xffffff0` убирается.

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

`state == "up" || state == "unknown"` — оба активные. DOWN → `blackhole`-маршрут в таблице.

#### Настройка маршрутов (`drm_setup_all_routes`)

```
ip [-6] rule  add priority N fwmark 0x<mark> table <tableID>
ip [-6] route add default dev <interface> table <tableID>   # или blackhole если DOWN
```

`"can't find device"` → `blackhole` вместо ошибки.

**IP Rule Priority:** `9 - (table_id - table_start)`, минимум 1.

#### Прочие функции

- `drm_scan_interfaces()` — читает `/sys/class/net/`, для каждого только `operstate`
- `drm_classify_target()` — линейный поиск по имени в `interfaces[]`
- `drm_update_used_states()` — обновляет `operstate` только для `routes[]`
- `drm_get_states(drm, states, count)` — снимок текущих состояний `routes[]` перед обновлением
- `drm_handle_state_changes(drm, old_states, old_count)` — сравнивает старые и новые; при изменении — `drm_update_route_on_state_change()` (flush + новый маршрут)

---

## 9. Обработчик сигналов: `src/signal_handler.c`

`signal_mgr_t { sig_fd, timer_fd }` — один контейнер для `signalfd` и debounce-`timerfd`.

### `signal_mgr_init(m)`

- `sigprocmask(SIG_BLOCK, ...)` повторно (`main` уже блокирует) — защита
- `signalfd(SFD_CLOEXEC)` → `m->sig_fd`
- `timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)` → `m->timer_fd`

### Прочие функции

- `signal_mgr_close(m)` — close обоих `fd`
- `signal_mgr_arm_timer(m, seconds)` — one-shot через `timerfd_settime`
- `signal_mgr_read_timer(m)` — `read()` expirations

### Логика обработки (`main.c`, epoll loop)

**`SIGUSR1`:**

- `timer_active=false`: `perform_update()` (при `g_drm_active` — `drm_get_states` + `drm_update_used_states` + `drm_handle_state_changes`; всегда — `apply_unified_connmark_rules`; при `g_l7_active && g_l7_wan[0]` — `l7_firewall_install`); `signal_mgr_arm_timer(5)`; `timer_active=1`
- `timer_active=true`: `pending_update=1`

**Debounce timer expired:**

- `signal_mgr_read_timer`; если `pending_update=1` → повторный `perform_update()`; сброс `timer_active=0` и `pending_update=0`

**`SIGINT`/`SIGTERM`:** `g_shutdown=1` → выход из epoll loop → cleanup.

---

## 10. Файл конфигурации: `src/config.c` + `src/params.c`

Формат: `key=value`, комментарии `#`, пустые строки игнорируются. `GeoIPFile` и `GeoSiteFile` могут повторяться (до `MAX_GEO_FILES=16`). `PolicyOrder` — через запятую, до `MAX_POLICY_ORDER=64`.

Описание параметров — таблица `PARAMS[]` в `src/params.c` (`param_def_t`: `config_key`, `cli_flag`, `type`, offset-ы в `config_t` и `cli_args_t`, `set_bit`, `default_int`, `help_arg`, `help_text`, `help_default`). Один ряд на параметр, драйвит `config_read`, `args_parse`, `args_apply`, `print_help`, `config_generate`. Типы: `PT_BOOL`, `PT_INT`, `PT_INT_POS`, `PT_STRING`, `PT_PATH`, `PT_REPEAT_PATH`, `PT_POLICY_ORDER`.

### `config_read(path, cfg)`

- `memset(cfg, 0)` + применение `default_int` / `help_default` для каждого `PARAMS[i]`
- `fopen(path)`; при ошибке возвращает `-1` (но `main` продолжит, если путь дефолтный)
- `getline` по строкам, `key=value` через `apply_kv(cfg, p, val)`

### `config_generate(target)`

- `target` пустой → `hrneo.conf` рядом с бинарём (`readlink /proc/self/exe → dirname`)
- `target`-каталог (или со слешем) → `<dir>/hrneo.conf`
- `target`-файл → записывается ровно по пути
- Записывает все 27 ключей с дефолтами; пустые multi-value ключи как `Key=`

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
| `set_mask` `uint32_t` | битовая маска: по одному биту на каждый параметр |
| зеркало всех полей `config_t` | для каждого `PARAMS[i]` |

### `args_parse(argc, argv, out)`

- `memset(out, 0)` в начале
- `--version`/`-v`: `printf "hrneo vVERSION"`, возвращает 1
- `--help`/`-h`: выводит справку, возвращает 2
- `--config <path>`: парсит путь, продолжает
- `--genconfig [path]`: возвращает 3 (`main → config_generate`)
- Для всех остальных флагов — поиск по `PARAMS[]`; неизвестный → `"unknown option"`, `return -1`
- `apply_cli_value()` по типу параметра: `PT_BOOL` (`"true"`/`"false"`), `PT_INT/POS` (`strtol`), `PT_STRING/PATH` (`strncpy`), `PT_REPEAT_PATH` (накапливает в массив), `PT_POLICY_ORDER` (`strtok_r` по запятой)
- При успехе `set_mask |= p->set_bit`
- Возвращает `0` (успех), `1` (`--version`), `2` (`--help`), `3` (`--genconfig`), `-1` (ошибка)

### `args_apply(args, cfg)`

- Для каждого `PARAMS[i]` с `set_mask & p->set_bit` — копирует поле из `args` в `cfg`
- `PT_REPEAT_PATH` / `PT_POLICY_ORDER` заменяют массив полностью

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
| `3` | Full (только точное имя) | `ht_insert` с `match_subs=0` |

### Парсинг `.dat`-файлов

- Формат: v2ray/xray protobuf, потоковое чтение (`setvbuf 64КБ`)
- `read_varint()` / `read_varint_stream()` для streaming
- `scan_dat_file(file, target_upper, visitor, ctx)` — generic stream-сканер (visitor-pattern: `count_geoip_visitor` / `extract_geoip_visitor` / `extract_geosite_visitor`)
- `extract_geoip_cidrs(file, country)` — полный скан до EOF
- `extract_geosite_domains(file, tag)` — полный скан до EOF
- `parse_geoip_body()`, `parse_cidr_body()`, `parse_geosite_body()`, `parse_geosite_domain()` — ручной protobuf-парсинг

### `deduplicate_domains(domains, count)`

1. Фильтрует только `Type=2` и `Type=3`
2. Сортирует по количеству точек (от меньшего к большему — root → leaf)
3. Удаляет поддомены через временную хеш-таблицу: если домен суффикс уже принятого — отбрасывается

### `parse_geosite_rules(watchlist_path, rules, max_rules)`

- Читает `domain.conf` через `getline()`, собирает все `geosite:`-записи
- Возвращает `geosite_rule_t[]` (`tag + policy_name`)

### `build_geosite_domain_map(filePaths, fileCount, rules, ruleCount, ht)`

- Для каждого `rule.tag` обходит все `filePaths`, объединяет домены, `deduplicate`
- `Type=2`: `ht_insert(val, match_subs=1)`
- `Type=3`: `ht_insert(val, match_subs=0)`
- `ht_insert` не перезаписывает существующие → приоритет у `domain.conf`

### `add_cidr_to_ipsets(mgr, cidr_path, pairs, pair_count, enable_timeout, timeout, geoip_files, geoip_count, maxelem)`

`effective_limit = (maxelem > 0) ? maxelem : IPSET_DEFAULT_MAXELEM (262144)`.

#### Фаза 1 (пресканирование CIDRfile при `geoip_count > 0`)

- `scan_cidrfile_blocks(verbose=0)` + `phase1_on_entry`
- Собирает все уникальные `geoip:TAG` из активных блоков
- Для каждого нового тега → `count_geoip_cidrs_all_files()` → `geoip_tag_count_t` кэш
- **Oversized:** `tag.ipv4 > effective_limit || tag.ipv6 > effective_limit`
- При oversized → `LOG_WARN` + `cidrfile_migrate_oversized()` → `LOG_INFO`

#### `cidrfile_migrate_oversized(path, oversized[], count)`

- Читает строки через `getline()` (до `CIDR_MIGRATE_MAX_LINES=16384`), сохраняет `strdup` в массив `cidr_line_t`
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

- `ipset_refresh_set_list()` + cache `timeout` для всех пар
- `scan_cidrfile_blocks(verbose=1)` + `phase2_on_entry`
- Блок активен если `ipset_set_exists()` для ipv4 ИЛИ ipv6 имени
- Oversized теги пропускаются
- Для каждого `geoip:TAG`: cumulative check `usage[v4_target].count + cached_ipv4 > effective_limit` → `LOG_WARN` + `allow_v4=0`; аналогично IPv6
- GeoIP-записи и статические CIDR группируются в `batch_t` по `target_set` (`batch_find_or_add` через open-addressed FNV-1a индекс, `NAME_INDEX_SLOTS=256`)
- Статические CIDR: `usage[target_set].count + 1 > effective_limit` → одно `LOG_WARN` (`warned` флаг), пропуск
- Все батчи отправляются через `ipset_add_batch(with_timeout=0)` → постоянные записи

`usage[]`/`batches[]` адресуются через open-addressed FNV-1a индексы (`NAME_INDEX_SLOTS=256`) — заменяет `O(n)` линейный скан при большом числе целей.

---

## 13. RCI (Remote Configuration Interface) Keenetic: `src/rci.c`

### Архитектурное решение

hrneo взаимодействует с роутером Keenetic **исключительно через RCI HTTP/JSON API** на `127.0.0.1:79`. **НЕ используются:** `ndmc`, `ndmq`, `curl`, `wget`, `jq`, `python` и любые другие userspace-утилиты роутера. Весь HTTP-клиент и JSON-парсер — самописные, целиком в `src/rci.c` (~262 строки). Это:

- убирает зависимость от наличия и версий системных утилит на роутере
- устраняет `fork`/`exec` на каждое обращение (важно на `SIGUSR1`, где `apply_unified_connmark_rules` может делать до 5 запросов подряд)
- сохраняет совместимость со статической сборкой (никаких `libcurl`/`cJSON` в `LIBS`)
- даёт предсказуемые таймауты через `SO_RCVTIMEO`/`SO_SNDTIMEO`

### Константы (`include/rci.h`)

| Константа | Значение | Назначение |
|-----------|----------|------------|
| `RCI_PORT` | `DEFAULT_API_PORT` (79) | захардкожен, параметра конфига нет |
| `RCI_MAX_RESPONSE` | `1024 * 1024` (1 МБ) | буфер выделяется через `malloc` при `rci_client_init` |
| `POLICY_API_MAX_RETRIES` | `5` | попыток на `GET /rci/show/ip/policy/` |
| `POLICY_API_RETRY_DELAY` | `3` (секунды) | интервал между попытками |
| `RCI_TIMEOUT_SEC` | `10` | `SO_RCVTIMEO` и `SO_SNDTIMEO` |

### `rci_client_t { raw_buf, response_buf }`

- `raw_buf` — сырой HTTP-приём (`RCI_MAX_RESPONSE + 4096`; +4096 для заголовков)
- `response_buf` — буфер тела ответа после парсинга (`RCI_MAX_RESPONSE`)
- Оба выделяются в `rci_client_init()` и переиспользуются весь lifetime демона. Никаких `malloc` при `SIGUSR1` → нет фрагментации heap, нет latency

`rci_client_close`: `free` обоих буферов.

### Сетевой клиент

#### `rci_connect()`

- `socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)`
- `SO_RCVTIMEO` / `SO_SNDTIMEO` = 10 секунд (отдельно для send и recv)
- `connect` к `127.0.0.1:79` (`INADDR_LOOPBACK` через `htonl`)
- HTTP/1.0 `Connection: close` (по умолчанию) — каждый запрос = новое TCP-соединение, ответ читается до EOF (закрытия сокета сервером)

#### `rci_request(c, method, path, body, body_len, response, response_max)`

1. `rci_connect`; при неудаче — `LOG_ERROR` + `return -1`
2. Формирование HTTP-заголовка через `snprintf` (не `fork+printf`):

   ```http
   <METHOD> <PATH> HTTP/1.0
   Host: localhost
   Content-Type: application/json     # только при body
   Content-Length: <N>                # только при body

   ```

3. `send` заголовка; при `body` — отдельный `send` цикла `body_len` байт
4. `recv` цикл в `c->raw_buf` (до `RCI_MAX_RESPONSE+4096-1` байт или EOF/0)
5. Парсинг ответа:
   - `strstr("\r\n\r\n")` — граница заголовков и тела
   - `strncmp(raw, "HTTP/", 5)` — sanity-check
   - `strchr(raw, ' ') + atoi` — код статуса; не 200 → `LOG_ERROR` + `return -1`
6. `memcpy` тела в `response` (обрезка до `response_max-1`)

### Парсер JSON ответа `/rci/show/ip/policy/`

Ответ имеет стабильный формат (политики Keenetic — простая структура, безопасно парсить вручную):

```json
{
  "HydraRoute": {"description":"...", "mark":"0x21", ...},
  "RU":        {"description":"...", "mark":"0x22", ...}
}
```

#### `find_matching_brace(open_brace)` — сканер с подсчётом фигурных скобок

- `depth++` на `{`, `depth--` на `}`; возврат при `depth==0`
- `in_string`-флаг переключается на не-экранированной `"`; внутри строки скобки игнорируются (защита от литералов вида `"value with {}"`)
- Не полноценный JSON-парсер (нет обработки escape-последовательностей внутри значений, нет валидации синтаксиса); достаточно для формата RCI

#### `rci_get_policies(c, policies, max_policies)`

1. `rci_request GET /rci/show/ip/policy/`
2. Поиск первого `{` (root)
3. Цикл по парам `{key: {...}}`:
   - `strchr('"')` / `strchr('"')` — извлечение имени политики (`key`)
   - `strchr('{')` + `find_matching_brace` — границы объекта
   - В объекте: `strstr("\"mark\"")` → `strchr(':')` → `strchr('"')` → `strchr('"')` — извлечение значения `mark`
   - Префикс `"0x"`/`"0X"` в начале значения удаляется (для прямой подстановки в `--set-xmark`)
   - `policy_mark_t { name[MAX_POLICY_NAME=64], mark[16] }` заполняется
   - `LOG_DEBUG "RCI policy: %s mark=0x%s"`
4. Возврат `count` политик

Политики **БЕЗ** ключа `"mark"` (например, только что созданные роутером, у которых ещё не назначен идентификатор маркировки) пропускаются — будут дозаявлены на следующей итерации retry-loop.

#### `rci_get_policies_with_retry(c, policies, max_policies)`

- До `POLICY_API_MAX_RETRIES=5` попыток с интервалом `POLICY_API_RETRY_DELAY=3` секунды; `LOG_WARN` при неудаче, `LOG_ERROR` при исчерпании
- Этот wrapper защищает от транзитных проблем сети/перегрузки `ndmsv`; если roundtrip <10s — все 5 попыток успеют до общего timeout

### Создание политик

#### `rci_create_policies(c, names, count)`

1. Формирование тела `POST` вручную:

   ```json
   [{"parse":"ip policy <name1>"},
    {"parse":"ip policy <name2>"},
    ...]
   ```

   (массив до 4 КБ; ~50 байт на политику, до ~80 политик в одном запросе). Команда `parse` эквивалентна вводу строки в CLI Keenetic — `ip policy <name>` создаёт пустую политику если её нет, no-op если есть.
2. `POST /rci/` с этим body
3. `LOG_INFO "Policy creation commands executed"`
4. Безусловный вызов `rci_save_config()` — иначе изменения не сохранятся в startup-config роутера и пропадут при перезагрузке

#### `rci_save_config(c)`

- `POST /rci/` с `{"system":{"configuration":{"save":true}}}`
- Эквивалент `system configuration save` в CLI

### Интеграция с остальным кодом

#### `main.c` (порядок старта)

- 14. `rci_client_init(&g_rci)` — однократное выделение буферов
- 15. `rci_create_policies(&g_rci, policy_names, policy_count)` — создание политик для всех целей-политик (интерфейсы DirectRoute сюда не попадают)
- 20. `apply_unified_connmark_rules(&g_rci, ...)` — первое применение правил

#### `iptables.c::apply_unified_connmark_rules` — вызывается при старте и на `SIGUSR1`

Шаг 2: retry loop (до 5, sleep 4s) — внутри `rci_get_policies_with_retry` + проверка наличия `mark` для каждой не-interface цели. Если хотя бы у одной политики `mark` пустой (только что создана, роутер ещё не назначил `markID`) → повтор всего блока через 4 секунды. Двухуровневая защита: `rci_get_policies_with_retry` ловит сетевые ошибки/таймауты, apply-loop ловит «политика создана, но без `markID`».

Если после всех попыток `markID` не появился — `LOG_WARN "Policy %s has no mark ID, skipping"`. Цель пропускается в этой итерации правил, но `ipset` продолжает заполняться DNS/L7-каналами. На следующем `SIGUSR1` цикл повторяется.

> **Главное правило:** hrneo не молчит при проблемах с RCI, но и не валится — при недоступности роутера демон продолжает работать в degraded-режиме (`ipset` заполняется, конкретные политики временно без CONNMARK-правил).

### Системные требования

- Демон запущен от root (доступ к `loopback:79` + локальная аутентификация NDM, для root прозрачна)
- RCI на роутере включён (на всех современных прошивках Keenetic v3+ — да, по умолчанию)

---

## 14. Netlink Conntrack: `src/conntrack.c`

`conntrack_mgr_t { fd }` — long-lived `NETLINK_NETFILTER` сокет (init однократно в `main`, закрывается при выходе).

### `conntrack_flush_for_ips(m, new_ips, count)`

1. Разбивает на `ipv4_set[64][16]` и `ipv6_set[64][16]` по семейству
2. Для непустых множеств вызывает `ct_flush_family(m->fd, ...)`

### `ct_flush_family(fd, family, targets, target_count, ip_len)`

1. `IPCTNL_MSG_CT_GET + NLM_F_DUMP` — все conntrack-записи семейства
2. Для каждой записи: `ct_extract_orig_tuple()` → dst IP → `memcmp` с `targets`
3. `ct_delete_entry()` при совпадении (`IPCTNL_MSG_CT_DELETE` с тем же `orig tuple`); счётчик удалений в `LOG_DEBUG`

### Прочие функции

- `ct_extract_orig_tuple()` — ищет `CTA_TUPLE_ORIG` (маска `NLA_TYPE_MASK=0x7FFF`)
- `ct_extract_dst_ip()` — из `CTA_TUPLE_IP` → `CTA_IPV4_DST`/`CTA_IPV6_DST`

---

## 15. Логирование: `src/log.c`

Глобально: `int log_enabled`, `static int log_syslog`, `static FILE *log_fp`. Сборщика статистики (`monitor_stats_t`) нет.

### Уровни логирования (макросы в `include/log.h`)

- `[DEBUG]` / `[INFO]` / `[MATCH]` / `[PROCESSED]` / `[FILTERED]` — выводятся только при `log_enabled=1`
- `[WARN]` / `[ERROR]` — выводятся всегда; если `log_fp=NULL` → `stderr`; при `log_syslog=1` → `vsyslog(LOG_INFO)`

### `log_setup(cfg)`

| Значение `log` | Поведение |
|----------------|-----------|
| `console` | `log_fp=stdout`, `log_enabled=1` |
| `file` + `log_file_path[0]!=0` | `mkdir_p` + `fopen(append)`, `log_enabled=1`; пустой путь → `log_enabled=0`, `return 0` |
| `syslog` | `openlog("hrneo", LOG_PID|LOG_NDELAY, LOG_DAEMON)`; `log_syslog=1`, `log_enabled=1` |
| default (`off` и любое другое) | `log_fp=NULL`, `log_enabled=0` |

`log_close()`: `fclose()` если `log_fp` не `stdout`/`stderr`; `closelog()` если `log_syslog=1`.

### О счётчиках L7

L7-диспетчер содержит `static uint64_t`-счётчики (`stat_too_short`, `malformed`, `not_tcp`, `wrong_flags`, `empty`, `wrong_port`, `not_tls`, `tls_no_sni`, `tls_matched`, `not_http`, `http_no_host`, `http_matched`, `bogon`, `disabled`, `reasm_started`, `reasm_completed`) в `src/l7_dispatch.c` — инкрементируются на hot path. Поля `stat_started`/`completed`/`evicted`/`expired`/`drop_gap`/`too_big`/`retransmit` есть и в структуре `tcp_reasm_t` (`src/tcp_reasm.c`) — также инкрементируются.

Однако функция `l7_dispatch_dump_stats()` (единственное место, где какие-либо счётчики читаются и выводятся в `LOG_INFO`) **НИГДЕ** не вызывается из основного кода — объявлена в API заголовка, не интегрирована ни в loop, ни в обработчики сигналов. Поля `tcp_reasm_t.stat_*` не читаются вообще нигде (`dump_stats` работает только со static-счётчиками `l7_dispatch.c`, не с `g_reasm`).

> В текущей версии счётчики — мёртвый код, запас под будущую диагностику.

---

## 16. Система сборки: Makefile

**Версия:** 3.11.0-1
**Язык:** C (без CGO, без внешних библиотек)

### Кросс-компиляция

| Цель | Компилятор | Флаги |
|------|------------|-------|
| `mipsel` | `mipsel-linux-gnu-gcc` | `-march=mips32r2 -mtune=1004kc -EL -mno-check-zero-division -mno-shared -mno-plt`, static |
| `mips` | `mips-linux-gnu-gcc` | `-march=mips32r2 -mtune=1004kc -mno-check-zero-division -mno-shared -mno-plt`, static |
| `aarch64` | `aarch64-linux-gnu-gcc` | `-march=armv8-a -mno-outline-atomics -fno-exceptions`, static + `-Wl,--strip-all -Wl,-z,norelro` |
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

23 исходных файла (`src/*.c`), заголовочные в `include/`. Никаких `LIBS`/`LDFLAGS` для L7 — `NFQUEUE` через стандартные kernel-заголовки `<linux/netfilter/nfnetlink_queue.h>`.

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
- **aarch64-3.10:** бинарь дополнительно сжимается через `upx --best`
- **Зависимости ipk:** `libc`, `ipset`, `iptables`, `ip-full`
- **conffiles:** `/opt/etc/HydraRoute/{hrneo.conf, domain.conf, ip.list}`
- В пакете: минимальный `hrneo.conf` (`log=off`, `logfile=...`, `PolicyOrder=HydraRoute`; остальные ключи возьмут встроенные дефолты), стартовый `domain.conf` (Youtube/Google/Telegram/AI/Other/2ip), `ip.list` с CIDR Telegram

---

## 18. L7-перехват: TLS SNI / HTTP Host / TCP-реассамблеция

Второй источник имён хостов параллельно DNS-каналу. Активируется `l7CaptureEnabled=true`. Закрывает слепые зоны DNS-only схемы: клиенты с DoH/DoT/DoQ, hardcoded-IP TLS, легаси-HTTP, тёплый DNS-кэш устройства.

### 18.1 Цепочка

```
[Клиент LAN→WAN TCP 443/80]
    → iptables/ip6tables mangle/POSTROUTING -o WAN -p tcp --dport 443|80
      --tcp-flags SYN,ACK ACK -m connbytes 2:N -m length 60: -j NFQUEUE
    → nfq_capture (raw NETLINK_NETFILTER, ACCEPT verdict)
    → l7_dispatch_packet (fail-fast IP/TCP/dport)
    → probe_tls/probe_http (stateless парсеры) + tcp_reasm (фаза 2)
    → bogon_check → process_hostname_event_l7 → общий путь DNS-канала
      (match_domain_with_cname → ipset_add_batch → conntrack_flush)
```

Логи различают источник тегом: `[DNS]` / `[TLS-SNI]` / `[HTTP-Host]`.

### 18.2 Модули

- **`src/probe_tls.c`:** `tls_quick_check` (`d[0]=0x16, d[1]=0x03, d[2]<=0x03, d[5]=0x01`), `tls_extract_sni` (record→handshake→ext→SNI type 0, partial-OK, lowercase).
- **`src/probe_http.c`:** case-insensitive `"\nHost:"`, порт обрезается, IPv6-литерал `[::1]` поддержан.
- **`src/bogon.c`:** служебные IPv4 (`0/8, 10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, >=224`) и IPv6 (`ff00::/8, fc00::/7, fe80::/10, ::, ::1, ::ffff:0:0/96`).
- **`src/nfq_capture.c`:** свой NFQUEUE-клиент без `libnetfilter_queue` (`NFNL_SUBSYS_QUEUE=3`, `PF_BIND`→`CMD_BIND`→`PARAMS`→`FLAGS`, `recv MSG_DONTWAIT`, `NFQNL_MSG_VERDICT=NF_ACCEPT`). `nfq_capture_t { fd, qnum, seq, portid, callback, user_data, stat_recv/pass/err, recv_buf[NFQ_RECV_BUF_SIZE=128KB] }`. Защита от `ENOBUFS` (`stat_err++` + `LOG_WARN`).
- **`src/l7_firewall.c`:** `l7_firewall_resolve_wan` (config + `stat /sys/class/net`, иначе `/proc/net/route Destination==00000000`), `l7_firewall_load_kmod` (`init_module(2)`, нет `modprobe` на Keenetic), `install/remove` (`fork+exec iptables`, `-C ... || -A` для идемпотентности; `-D` в цикле). Для `dport 80` `connbytes_max` ужимается до `min(N, 4)`.
- **`src/l7_dispatch.c`:** каскад + `try_tls_extract` (fast-path / reasm), `l7_dispatch_set_enable` / `set_reasm`, `dump_stats`.
- **`src/tcp_reasm.c`** (фаза 2): 5-tuple хеш (`TCP_REASM_BUCKETS=64`), пул `calloc-on-init` (`l7TcpReasmMaxEntries × TCP_REASM_BUF_SIZE=16KB`), `start/feed/complete/get/destroy/gc`, seq-упорядочивание (gap→drop, retransmit→no-op), LRU-eviction, `timerfd` GC (TTL `l7TcpReasmTtlSec`). Поля счётчиков (`stat_started`/`completed`/`evicted`/`expired`/`drop_gap`/`too_big`/`retransmit`) есть в структуре `tcp_reasm_t` и инкрементируются на hot path, но в текущей версии нигде не читаются и не выводятся (`l7_dispatch_dump_stats` оперирует своими статическими счётчиками, не полями `g_reasm`; сама `l7_dispatch_dump_stats` нигде не вызывается из основного кода — функция объявлена в API заголовка, но не интегрирована в loop/сигналы). Фактически это запас под будущую диагностику; на работу демона не влияет.

### 18.3 Архитектурные решения

- Вся системная логика в C-демоне; shell-хук `015-hrneo.sh` «тонкий» (только `kill -USR1`). Нет «зомби-скриптов» при остановленном демоне. `S99hrneo` минимальный.
- Один NFQ-сокет; диспетчер разводит по `dport`.
- Идемпотентность к DNS: `ipset_add_batch` с `NLM_F_EXCL` → двойное добавление IP no-op. Два источника (DNS + L7) безопасно пересекаются.
- **GRO coalescing:** на роутере с GRO ядро склеивает TCP-сегменты до netfilter → NFQUEUE видит CH целиком даже Kyber-размера → fast-path. Реассамблеция фазы 2 — страховочная сетка (GRO off / разные CPU / MSS-clamp / PMTU-дробление).

### 18.4 Известные gaps (НЕ реализовано)

- **QUIC / HTTP-3 (UDP/443)** — значимо для Apple-устройств (Safari/iCloud/Push активно используют h3)
- **ECH (Encrypted ClientHello)** — нерешаемо без MITM
- **iCloud Private Relay** — зашифрованный туннель, SNI релея (by design не наш)

---

## 19. Реализованные оптимизации

> Бо́льшая часть сведений потеряна т.к. не документировалась.

- **Однопоточная event-driven архитектура.** epoll-цикл: `cap.fd4` + `cap.fd6` + `signals.sig_fd` + `signals.timer_fd` + (опц.) `nfq_fd` + `reasm_gc_fd`. Без GC, без потоков, без каналов.
- **Netlink вместо `fork`/`exec` для ipset.** Все `CREATE`, `FLUSH`, `ADD` через прямой netlink-сокет (`NETLINK_NETFILTER`, long-lived).
- **Батчевая отправка ipset через netlink.** `ipset_add_batch()`: чанки по 256 — send N сообщений, затем recv N ответов. Kernel обрабатывает очередь параллельно с чтением ответов.
- **`iptables-restore` для batch-правил.** `apply_unified_connmark_rules()`: все `CONNMARK`-правила одним вызовом `iptables-restore --noflush`.
- **Хеш-таблица доменов с chunked pool.** 8192 бакетов, FNV-1a, цепочки. Chunked pool 256КБ с автоматическим расширением — ноды и строки в одном аллокаторе. Дедупликация `ipset_name` через `ipset_name_cache[]`.
- **Суффиксный матчинг через хеш-таблицу.** Для каждой точки в домене проверяется parent-домен — `O(количество точек)`, каждая `O(1)` средний.
- **Кэш ipset-списков и timeout.** `set_names[]` (cache `ipset list -n` при старте) + `set_has_timeout[256]` / `timeout_value[256]` по FNV-1a индексу.
- **Open-addressed FNV-1a индексы.** В `geodat` для `batches[]` и `usage[]` (`NAME_INDEX_SLOTS=256`) — заменяет `O(n)` линейный поиск при большом числе целей.
- **Debounce SIGUSR1.** `timerfd`: повторный `SIGUSR1` во время обработки откладывается на 5 секунд.
- **Conntrack flush через netlink.** Long-lived netlink-сокет (init однократно). Один DUMP на семейство + DELETE по совпадению. Без `fork`/`exec`.
- **Стриминговый парсинг .dat-файлов.** Потоковое чтение через `setvbuf(64KB)`. В памяти хранятся только извлечённые записи. Visitor-pattern (`scan_dat_file`).
- **Статическая аллокация в hot path.** `dns_result_t` (static в `process_dns_packet`), `cname_entry_t` (static), `processed[]`, `ipv4_batch[]`, `ipv6_batch[]`, `all_new[]` — на стеке, без `malloc`.
- **Unified targets.** `g_all_sorted[]` объединяет политики и интерфейсы в единый отсортированный массив. `apply_unified_connmark_rules()` обрабатывает все цели одним проходом.
- **Дедупликация указателей `ipset_name`.** `ht_insert()` ищет существующий указатель через `ipset_name_cache[]` перед аллокацией нового.
- **AF_PACKET SOCK_DGRAM + L3-BPF в ядре.** BPF-фильтры на сокетах через `SO_ATTACH_FILTER`. Ядро отбрасывает нерелевантные пакеты до копирования в userspace — только DNS-ответы достигают `process_dns_packet`. `SOCK_DGRAM` отдаёт пакет с IP-уровня единообразно для всех типов интерфейсов, поэтому фильтр работает по IP-версии/протоколу/порту без привязки к Ethernet-кадру.
- **Контроль maxelem.** Предварительный подсчёт geoip-записей (`count_geoip_body` без аллокаций) + автомиграция oversized `geoip:TAG` в disabled-секцию `CIDRfile` (атомарно через `.tmp + rename`).
- **Table-driven config.** `PARAMS[]` (`src/params.c`) — одно описание параметра обслуживает `config_read`, `args_parse`/`args_apply`, `print_help`, `config_generate`.
- **L7 fail-fast каскад.** Длина → IP-версия → TCP → флаги → dport → 1-байтовая сигнатура TLS/HTTP → парсер. Реассамблеция запускается только для фрагментированных CH (fast-path для коротких). Один NFQ-сокет.

---

## Резюме

**HRNeo v3.11.0-1** — компактный однопоточный policy routing демон для роутеров Keenetic, написанный на чистом C.

Два источника имён хостов:

- **DNS-канал** — перехват DNS-ответов через AF_PACKET SOCK_DGRAM + L3-BPF, два fd; работает на интерфейсах любого типа (Ethernet, PPP, ARPHRD_NONE, туннели), поэтому ловит DNS LAN- и VPN-клиентов одним кодом
- **L7-канал** — TLS SNI / HTTP Host исходящих соединений через собственный NFQUEUE-клиент на raw netlink, при `l7CaptureEnabled`; фаза 2 — TCP-реассамблеция фрагментированных ClientHello

Извлекает IP-адреса и добавляет в `ipset` через netlink, маркирует трафик в `iptables/mangle` для policy routing. Поддерживает маршрутизацию через политики Keenetic (mark через RCI API) и прямую на интерфейсы (`fwmark` + `ip rule` + `ip route`). GeoIP/GeoSite из `.dat` v2ray/xray с потоковым protobuf-парсингом.

Event-driven архитектура на `epoll` (`cap.fd4` + `cap.fd6` + `signalfd` + `timerfd` + `nfq_fd` + `reasm_gc_fd`). QUIC/HTTP-3 — НЕ реализовано (gap для Apple/h3-трафика).

**27 параметров конфига**, все доступны через CLI-флаги (`--flag value`) + `--config <path>`, `--version`/`-v`, `--help`/`-h`, `--genconfig [path]`; приоритет: CLI > конфиг > дефолты. Описание параметров — единая таблица `PARAMS[]` в `src/params.c`, драйвит `config_read`, args, `--help`, `--genconfig`.

**Оптимизирован:** батчевый netlink (send N / recv N), хеш-таблица доменов 8192 бакетов с chunked pool (256КБ чанки), unified targets, batch `iptables-restore`, debounce сигналов, conntrack flush через netlink с long-lived сокетом, статическая аллокация в hot path, двунаправленный CNAME BFS, BPF-фильтрация в ядре, `ipset CREATE` с автоматическим запросом kernel-revision, контроль `maxelem` с автомиграцией oversized `geoip:TAG` в disabled-секцию `CIDRfile`.
