# Исправление ошибки загрузки ASU в LuCI

Если LuCI показывает `"ax6000_asu" factory yields invalid constructor`, встроенный модуль ASU возвращает обычный объект вместо класса LuCI. Исправление добавляет `baseclass.extend()`; правила выбора поколения, разметки и пакетов сохраняются.

Исходник исправлен в `ed74b6b3139240820b88ecd3a2310642bbd84dd4`. Уже выпущенные неизменяемые образы и APK r2 содержат прежний файл. Исправленный исходник пакета использует APK r3; наличие исходника ещё не означает, что обновлённый пакет или новая прошивка уже опубликованы.

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

Новый модуль проверен настоящими `Class` и `require()` из закреплённого LuCI, включая прежний ошибочный случай. Полный набор: 525 тестов, один пропущен. Это не проверка готовности HTTPS-сервера ASU или обновления физического устройства.
