# Публикация проверенной сборки 6.12

Перед публикацией должны пройти полная сборка, `verify-firmware.py` для всех
трёх образов и отдельная сборка свежих пакетов/AmneziaWG из экспортированного
SDK с сохранением kernel context и штатных kmods. Компиляция не подтверждает
работу на физическом роутере. Эти проверки выполняются до необратимой
публикации Release.

Нужны Pages с источником GitHub Actions, включённые immutable releases,
`OPKG_SIGNING_KEY` в repository secrets и соответствующий закреплённому
`keys/repository.pub` приватный ключ вне Git. Нельзя отправлять его в чат,
архивы сборки или логи.

## Неизменяемое поколение прошивки

Использовать тот же API-клиент, который применяется в CI. Он проверяет raw
inventory, SDK, три layouts, исходный профиль, архив и локальную подпись до
записи Release, сверяет SHA256/размер всех upload и лишь затем публикует draft.
Подписанный `downloads.json` фиксирует реальные asset IDs и ссылки именно
этого поколения. Образы и SDK хранятся в Release, а не копируются на Pages.

Архив содержит содержимое проверенного raw, только regular files/directories,
без ключей, symlinks и специальных файлов. Импорт ограничен 8 GiB и проверяет
полный inventory. Сохранить `recipe_commit` из firmware-manifest: tag должен
указывать на фактический рецепт сборки.

```sh
# GH_TOKEN передаётся в окружении локального процесса, без вывода значения.
python3 scripts/channel-snapshot.py publish-generation \
  --raw /absolute/raw \
  --expected-profile profiles/redmi-ax6000-612-recommended-new.json \
  --raw-archive /absolute/raw.tar.zst --checksum /absolute/raw.tar.zst.sha256 \
  --repository valujin/ax6000-packages-6.12 \
  --key /absolute/private-key --public-key keys/repository.pub \
  --usign /absolute/trusted-host-usign --output /absolute/fresh/generation
```

API не заменяет существующие draft, mutable release, tag другого commit или
asset другого SHA256. Полный готовый immutable набор можно использовать
повторно после проверки. Поколения каналов имеют разные build IDs и SDK.

## Подписанный snapshot и атомарный сайт

`publish-existing.yml` принимает точные `channel` и `release_tag`; для самой
первой публикации нужно явно `bootstrap=true`. Workflow импортирует поколение,
подписывает пакетный feed и выпускает отдельный immutable snapshot
`packages-CHANNEL-MANIFEST_SHA256`. Snapshot содержит все IPK, подписанные
индексы, профиль, lock, provenance и каталог загрузок, без крупных SDK/образов.

Сайт собирается из двух проверенных snapshots. Текущий `site-state.json`
подписан закреплённым ключом; он выбирает только последний успешно
развёрнутый набор. Перед deploy проверяется исходное состояние, после deploy
— SHA256 нового состояния и подписи. Upload snapshot без успешного deploy не
меняет live lock. Неизменяемый канал сохраняется побайтно.

Для повторной публикации и ежедневного обновления `bootstrap` запрещён.
Нельзя выбирать snapshot по latest Release: локальный snapshot или удачный
upload ещё не доказывает deployment. Ошибка оставляет последний live набор.

## Активация ежедневных обновлений

После всех фактических проверок, успешного deploy и независимой проверки
live подписей/контрольных сумм скопировать generated `raw/profile.json` в
`profiles/redmi-ax6000-612-CHANNEL.json` побайтно и commit/push. До появления
этого файла монитор отслеживает источники, но не публикует данный канал.

Ежедневный workflow использует exact source/ABI/SDK этого профиля;
обновляются feeds, Tailscale и AmneziaWG. Штатные kmods остаются из SDK baseline.
Две SDK сборки идут последовательно на GitHub hosted runner. Полное firmware
поколение автоматически не переключается; будущая смена ABI требует отдельной
политики сохранения уже выданных feeds. Прошивка и установка пакетов на роутер
остаются ручными действиями владельца.
