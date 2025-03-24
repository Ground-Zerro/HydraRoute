# HydraRoute

**Основная цель** — перенаправление трафика к **отдельным доменам** через VPN. Все, что не указано в списке, будет открываться напрямую.

Скрипт облегчает настройку раздельной маршрутизации трафика к доменам на роутерах **Keenetic**.
- Установка **"одной кнопкой"**.
- Никаких сложных настроек.

## Функции и возможности:
- Установка необходимых пакетов.
- Настройка и интеграция IPSet с AdGuard Home для управления маршрутизацией.
- Создание скриптов для динамической маршрутизации и маркировки трафика.
- Обход блокировки ECH Cloudflare.
- Установка DNS, защищенных шифрованием.
- Фильтрация рекламы.
    * Включены базовые фильтры рекламы, малваре и телеметрии Microsoft.
- Список доменов можно редактировать и расширять. После установки в него уже включены:
  - Youtube
  - OpenAI (ChatGPT)
  - И некоторые другие

## Требования:
- KeenOS версия 4.х (Работа на 3.х возможна, но не тестировалась).
- Развёрнутая среда [Entware](https://help.keenetic.com/hc/ru/articles/360021214160-Установка-системы-пакетов-репозитория-Entware-на-USB-накопитель).
- Настроенное VPN подключение.

## Установка:
Выберите версию **HydraRoute**
1. [v.0.0.1b](https://github.com/Ground-Zerro/HydraRoute/tree/main/beta001)
- Первая версия.
- Она работает.
- Добавление сервисов и блэклистов к списку доменов одной кнопкой.
- Поддержка работы с IPv6 *(если Ваш VPN сервер умеет маршрутизировать IPv6 трафик и провайдер+хостер предоставляют IPv6-адреса)*.

2. [v.0.0.2b](https://github.com/Ground-Zerro/HydraRoute/tree/main/beta002)
- Возможность выставления приоритетов подключений и их резервирование.
- Многопутевая передача Keenetic.
- Маршрутизация разных доменов в разные туннели.
- Резервирование подключений
- Управление подключениями производится в политиках доступа Keenetic.


## Удаление:
```
curl -Ls "https://raw.githubusercontent.com/Ground-Zerro/HydraRoute/refs/heads/main/uninstall.sh" | sh
```

## Планы на будущее
### To do
- ~~[Web панель в паблик релиз](https://github.com/Ground-Zerro/HydraRoute/tree/main/webpanel)~~ 30/01/2025
- ~~добавить дизайна~~ 22/02/2025 (в 0.0.2b)
- ~~авторизация в web панели~~ 23/03/2025 (в 0.0.2b)
- ~~загрузка сторонних списокв из сети~~ 23/03/2025 (в 0.0.2b)
- ~~[переписать установщик](https://github.com/Ground-Zerro/HydraRoute/blob/main/hydraroute.sh)~~ 01/02/2025
- придумать лого
- ipk формат
- поддержка dnsmasq
- полный отказ от сторонних DNS резолверов в пользу системного
- интеграция [zapret](https://github.com/bol-van/zapret/tree/master)
- обновление из WebUI

### Пожелания от пользоваталей
- ~~[boosty](https://boosty.to/ground_zerro)~~ 25/01/2025
- ~~опция: блокировать трафик если туннель не доступен (нет связи, отключен и т.п.)~~ 22/02/2025 (в 0.0.2b)
- ~~раздельная маршрутизация в два туннеля. Или в три?? ;)~~ 22/02/2025 (в 0.0.2b)
- опция: автоматическое обновление списокв по расписанию
- поддержка vless
- ~~[анигилятор](https://github.com/Ground-Zerro/HydraRoute/blob/main/uninstall.sh)~~ 28/01/2025
