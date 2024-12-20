# HydraRoute

**Основная цель** — перенаправление запросов к определенным доменам через VPN.

Скрипт облегчает настройку раздельной маршрутизации трафика к доменам на роутерах **Keenetic** с использованием связки ADGuard Home и IPSet.

## Функции и возможности:
- Установка необходимых пакетов.
- Настройка и интеграция IPSet с AdGuard Home для управления маршрутизацией.
- Создание скриптов для динамической маршрутизации и маркировки трафика.
- Обход блокировки ECH Cloudflare.
- Установка DNS, защищенных шифрованием.
- Поддержка IPv4 и IPv6.
- Фильтрация рекламы (при необходимости).
- Базовый список доменов для перенаправления, включающий сервисы (можно легко расширять):
  - Youtube
  - Instagram
  - OpenAI (ChatGPT)
  - Некоторые T-трекеры
  - Github

## Требования:
- KeenOS версия 4.х
- Развёрнутая среда [Entware](https://help.keenetic.com/hc/ru/articles/360021214160-Установка-системы-пакетов-репозитория-Entware-на-USB-накопитель).
- Рабочее, настроенное VPN-соединение поверх провайдерского, по которому будет идти обращение к выбранным доменам.
- Для работы через ipv6 - наличие рабочего ipv6 на основном подключении и на VPN-соединении.

## Как использовать:
1. Подключиться к роутеру по SSH (к Entware)
2. Выполнить код:
	```
	curl -L -s "https://raw.githubusercontent.com/Ground-Zerro/HydraRoute/refs/heads/main/hydraroute.sh" > /tmp/hydraroute.sh && chmod +x /tmp/hydraroute.sh && sh /tmp/hydraroute.sh
	```
3. Следовать инструкциям.
4. Завершить настройку AdGuardHome перейдя по адресу: [http://192.168.1.1:3000/](http://192.168.1.1:3000/) (где `192.168.1.1` - IP-адрес роутера).
5. Проверить работу перейдя на [2ip.ru](https://2ip.ru/). В поле `Ваш IP адрес:` должен отображаться IP-адрес подключения (VPN), через которое вы перенаправляете трафик.

## Дополнительная информация:
**Как добавить домены в ipset**
1. Чтобы добавить домены для перенаправления, отредактируйте файл: `/opt/etc/AdGuardHome/ipset.conf`.
	```
	nano /opt/etc/AdGuardHome/ipset.conf
	```
 
   <details>
   <summary>Синтаксис файла ipset.conf (нажать, чтобы прочесть подробней)</summary>
   
	```
	intel.com,2ip.ru/bypass,bypass6
	instagram.com,cdninstagram.com/bypass,bypass6
	openai.com,chatgpt.com/bypass,bypass6
	```
   
	- В левой части через запятую указаны домены, требующие обхода.
	- Справа после слэша — ipset, в который AGH складывает результаты разрешения DNS-имён. В примере указаны создаваемые скриптом `ipset` для IPv4 и IPv6: `/bypass,bypass6`
	- Можно указать всё в одну строчку, можно разделить логически на несколько строк как в примере.
	- Домены третьего уровня и выше включаются сами, т.е. указание `intel.com` включает также `www.intel.com`, `download.intel.com` и прочее.
	- В примере добавлен «сигнальный» сервис [2ip.ru](https://2ip.ru/), для проверки работоспособности решения, показывающий IP-адрес туннеля (VPN), через которое вы перенаправите трафик.
   </details>

2. После добавления доменов необходимо перезапустить **AdGuard Home** командой:
	```
	/opt/etc/init.d/S99adguardhome restart
	```
