# Исправления на установленном роутере

Команды ниже выполняются по SSH от root на нашей прошивке 6.12 с APK. Они исправляют отдельные файлы или подключение пакетов и не требуют перепрошивки. Это не сообщение о публикации новой прошивки или готовности сервера ASU.

## Подключение репозитория: `Architecture mismatch`

На Redmi AX6000 нормальна пара `apk --print-arch` → `aarch64` и `/etc/apk/arch` → `aarch64_cortex-a53`. Первая команда показывает архитектуру сборки клиента APK, файл задаёт архитектуру пакетов. Старый установщик ошибочно требовал их полного совпадения.

Исправленный установщик также принимает пять штатных `@public` feeds зеркала `mirrors.vsean.net` для 25.12.0 и `aarch64_cortex-a53`: base, luci, packages, routing, telephony. Скрипт первого запуска ImmortalWrt заменяет официальный адрес этим зеркалом; прежняя проверка его не учитывала. Чтение базы установленных пакетов теперь выполняется одним запросом APK вместо 262, а этапы и прогресс проверки выводятся в терминал.

Для канала `recommended` запустить исправленный установщик по закреплённой ссылке с проверкой SHA256:

```sh
sh <<'EOF'
set -eu
f=/tmp/ax6000-install-feed.fixed.sh
wget -O "$f" 'https://raw.githubusercontent.com/valujin/ax6000-packages-6.12/b122c35046ab1c3cd03828aabd168bb35466e2c8/scripts/install-feed-apk.sh'
echo 'cf09ea4a038f1080624aa5da534cc78871f70741b273db12515f875c9b484ebf  /tmp/ax6000-install-feed.fixed.sh' | sha256sum -c -
sh "$f"
if [ ! -e /root/ax6000-install-feed.before-fix ]; then
    cp -p /usr/sbin/ax6000-install-feed /root/ax6000-install-feed.before-fix
fi
cp "$f" /usr/sbin/ax6000-install-feed
chmod 755 /usr/sbin/ax6000-install-feed
EOF
```

Установщик проверяет подписанный профиль, ключи и точное совпадение ABI ядра, затем подключает свой репозиторий и выполняет `apk update`. Пакеты он не устанавливает.

Для уже установленного канала `latest` строку `sh "$f"` заменить на `PACKAGE_REPOSITORY_URL=https://valujin.github.io/ax6000-packages-6.12/channels/latest sh "$f"`. Для последующих запусков `latest` также нужен этот `PACKAGE_REPOSITORY_URL`.

После успешной проверки и подключения репозитория команды также сохраняют исправленный файл в `/usr/sbin/ax6000-install-feed`, оставляя первоначальную копию в `/root/ax6000-install-feed.before-fix`. Это рекомендуемое обновление сохраняет исправление для последующих запусков `ax6000-install-feed`; чтобы ограничиться одним запуском, можно опустить строки после `sh "$f"`. Перезагрузка не нужна.

## Ошибка загрузки ASU в LuCI

Если LuCI показывает `"ax6000_asu" factory yields invalid constructor`, встроенный модуль ASU возвращает обычный объект вместо класса LuCI. Исправление добавляет `baseclass.extend()`; правила выбора поколения, разметки и пакетов сохраняются.

Исправленный пакет `luci-app-attendedsysupgrade 20261021.2-r3` уже опубликован в подписанном feed recommended. После подключения feed исправленным установщиком обновить только приложение:

```sh
apk update
apk upgrade luci-app-attendedsysupgrade
apk --no-network query --installed --format json --fields name,version luci-app-attendedsysupgrade
```

Ожидаемая версия — `20261021.2-r3`. Затем обновить страницу браузера через Ctrl+F5. Эти команды не выполняют общее обновление всех пакетов и не закрепляют приложение на этой версии в `world`.

[Активация Pages 39694936141](https://github.com/valujin/ax6000-packages-6.12/actions/runs/39694936141) завершилась успешно. Текущий [подписанный снимок](https://github.com/valujin/ax6000-packages-6.12/releases/tag/packages-recommended-abe8541e34b2d302497ec38bbc39e040d96fe0f10c67684c6094c5f80cb25212) имеет SHA256 манифеста `abe8541e34b2d302497ec38bbc39e040d96fe0f10c67684c6094c5f80cb25212`. APK r3 размером 12 184 байта проверен по HTTPS, production-подписи индекса и штатным получением APK; его SHA256 — `6d54d2576ef2a92f0a577ffe0aa1ac58478e37cc44b877197480b9a59665f59c`.

Свежая проверка охватила 18 файлов recommended и подписанное состояние до/после. Неизменившиеся 1393 APK и 19 активов каталога опираются на ранее выполненную полную HTTPS-проверку 1437 файлов; повторно они не скачивались. Указатель latest сохранён. Receipt свежей проверки: SHA256 `7201c0754b41a4a5019e78ada913f27e035d93407c7b2098877e324142104c33`.

Исходник исправлен в `ed74b6b3139240820b88ecd3a2310642bbd84dd4`. Неизменяемые нативные образы и прежний APK r2 сохраняют старый файл. Публикация этого обновления пакета не меняет образы, SDK или ImageBuilder и не подтверждает готовность персональных образов ASU с r3, сервера ASU или аппаратное тестирование.

Если feed ещё не подключён, ниже остаётся способ исправить только файл по закреплённому исходнику.

Для установленного роутера выполнить по SSH от root. Команда скачивает файл по точному commit URL, проверяет SHA256 и сохраняет первоначальную резервную копию. Перезагрузка и перепрошивка не нужны.

```sh
sh <<'EOF'
set -eu
f=/www/luci-static/resources/ax6000_asu.js
[ -f "$f" ]
wget -O /tmp/ax6000_asu.fixed.js 'https://raw.githubusercontent.com/valujin/ax6000-packages-6.12/ed74b6b3139240820b88ecd3a2310642bbd84dd4/files/asu-client/ax6000_asu.js'
echo 'cbafbc641774f22ad1e47cbe8e1a8af80a8c1e36383c1d66d54dc40926ff23ff  /tmp/ax6000_asu.fixed.js' | sha256sum -c -
if [ ! -e /root/ax6000_asu.js.before-fix ]; then
    cp -p "$f" /root/ax6000_asu.js.before-fix
fi
cp /tmp/ax6000_asu.fixed.js "$f"
chmod 644 "$f"
echo 'ASU LuCI module fixed. Reload the browser page with Ctrl+F5.'
EOF
```

После выполнения обновить страницу браузера через Ctrl+F5. При необходимости возврата: `cp /root/ax6000_asu.js.before-fix /www/luci-static/resources/ax6000_asu.js`, затем снова Ctrl+F5.

Модуль проверен настоящими `Class` и `require()` из закреплённого LuCI. Это не проверка готовности HTTPS-сервера ASU или обновления физического устройства.

## Программы из публичных репозиториев: `@public`

Публичные репозитории помечены тегом `@public`. Поэтому обычная команда `apk add iperf3` может сообщить, что пакет `masked`: доступ к этим репозиториям включается явно для выбранной программы.

```sh
apk add iperf3@public
```

Зависимости получают доступ к тому же тегу автоматически; перечислять их вручную не нужно. В изолированной симуляции на подписанных индексах 25.12.0, сохранённых 21 октября 2026 года, команда выбрала только новые `libiperf3@public 3.20-r1` и `iperf3@public 3.20-r1`, без обновления, удаления или переустановки защищённых пакетов. Пакеты в проверке не устанавливались; версии в текущих индексах могут отличаться. Для другой публичной программы используется форма `apk add ИМЯ@public`.
