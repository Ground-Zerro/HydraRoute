# HydraRoute

**HydraRoute** — инструмент для раздельной маршрутизации трафика по доменам и CIDR с использованием туннелей на роутерах **Keenetic**.

Трафик к указанным доменам и CIDR отправляется через туннель, всё остальное — напрямую.

---

## Версии

### Neo

Актуальная версия.

[Подробная документация →](https://git.zerrolabs.org/Ground-Zerro/HydraRoute/tree/main/Neo)

### Classic — EOL

Жизненный цикл завершён. Поддержка прекращена.

[Архив →](https://git.zerrolabs.org/Ground-Zerro/HydraRoute/tree/main/Classic)

### Relic — EOL

Жизненный цикл завершён. Поддержка прекращена.

[Архив →](https://git.zerrolabs.org/Ground-Zerro/HydraRoute/tree/main/Relic)

---

## Быстрый старт (Neo)

```bash
opkg update && opkg install curl && curl -Ls "https://git.zerrolabs.org/Ground-Zerro/release/pages/keenetic/install-neo.sh" | sh
```

> **Требования:** роутер Keenetic с прошивкой выше v4.3.6, установленный Entware.

---

## Поддержать автора

[Boosty](https://boosty.to/ground_zerro)
