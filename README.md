# HydraRoute

**HydraRoute** — инструмент для раздельной маршрутизации трафика по доменам и CIDR с использованием туннелей на роутерах **Keenetic**.

Трафик к указанным доменам и CIDR отправляется через туннель, всё остальное — напрямую.

---

## Версии

### Neo — актуальная версия

DNS-based policy routing демон для Keenetic. Перехватывает DNS-ответы через NFLOG, добавляет IP в ipset через netlink, маркирует трафик в iptables.

- Не требует отключения системного DNS-сервера
- Прямая маршрутизация на сетевые интерфейсы (DirectRoute)
- Неограниченное количество политик маршрутизации
- GeoIP и GeoSite в формате v2ray/xray `.dat`
- Веб-интерфейс управления (HRweb)
- Полная поддержка IPv6

[Подробная документация →](https://github.com/Ground-Zerro/HydraRoute/tree/main/Neo)

### Classic — EOL

Жизненный цикл завершён. Поддержка прекращена.

[Архив →](https://github.com/Ground-Zerro/HydraRoute/tree/main/Classic)

### Relic — EOL

Жизненный цикл завершён. Поддержка прекращена.

[Архив →](https://github.com/Ground-Zerro/HydraRoute/tree/main/Relic)

---

## Быстрый старт (Neo)

```bash
opkg update && opkg install curl && curl -Ls "https://ground-zerro.github.io/release/keenetic/install-neo.sh" | sh
```

**Требования:** роутер Keenetic с прошивкой выше v4.3.6, установленный Entware, компонент «Xtables-addons для Netfilter».

---

## Поддержка

[Boosty](https://boosty.to/ground_zerro)
