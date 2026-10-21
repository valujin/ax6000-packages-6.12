# Redmi AX6000: vendor Linux 6.12 и подписанные пакеты

Две независимые линии на базе
[chasey-dev ImmortalWrt 25.12](https://github.com/chasey-dev/immortalwrt-mt798x-rebase).
Каждая выпускает образы **stock, mtkuboot и ubootmod**, свой SDK и банк модулей.
Разметки не взаимозаменяемы; установка выполняется владельцем вручную.

| Линия | Ядро | Закреплённые исходники | Новый Release |
| --- | --- | --- | --- |
| recommended | 6.12.108 | `ae65e1de69971b5a2e3cf7e39390ee93f274d488` | [Образы и SDK](https://github.com/valujin/ax6000-packages-6.12/releases/tag/firmware-redmi-ax6000-612-recommended-ae65e1de6997-6ef19743b104) |
| latest | 6.12.112 | `a99b0888b88f134f56bcb2a7d93027b5d20638a9` | [Образы и SDK](https://github.com/valujin/ax6000-packages-6.12/releases/tag/firmware-redmi-ax6000-612-latest-a99b0888b88f-0b1249707848) |

Начинать испытания с recommended и stock layout. Latest остаётся
экспериментальной: имеются upstream-сообщения о регрессиях HNAT; успешная
сборка не подтверждает работу аппаратного ускорения на физическом AX6000.
Регрессия NETSYS_V2 HNAT может затрагивать и обычную работу маршрутизатора;
пригодность latest для этого режима ещё не подтверждена.
[Подписанные feeds обеих линий](https://valujin.github.io/ax6000-packages-6.12/).
Линия [Linux 6.6](https://github.com/valujin/ax6000-packages) выпускается отдельно.

## Новые образы без встроенного Tailscale

**Tailscale исключён из initramfs и постоянного rootfs всех трёх разметок.**
Он сохранён как отдельный IPK в подписанном feed и участвует в ежедневных
обновлениях. AmneziaWG, WireGuard, PBR, LuCI и русский интерфейс остаются в
составе образа согласно `image_packages` source-профиля.

Нативный stock factory UBI теперь помещается в штатный раздел kernel **30 MiB**:

| Линия | Stock factory UBI | SHA256SUMS |
| --- | --- | --- |
| recommended | [17 825 792 байта](https://github.com/valujin/ax6000-packages-6.12/releases/download/firmware-redmi-ax6000-612-recommended-ae65e1de6997-6ef19743b104/immortalwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-stock-initramfs-factory.ubi) | [Суммы](https://github.com/valujin/ax6000-packages-6.12/releases/download/firmware-redmi-ax6000-612-recommended-ae65e1de6997-6ef19743b104/SHA256SUMS) |
| latest | [17 825 792 байт](https://github.com/valujin/ax6000-packages-6.12/releases/download/firmware-redmi-ax6000-612-latest-a99b0888b88f-0b1249707848/immortalwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-stock-initramfs-factory.ubi) | [Суммы](https://github.com/valujin/ax6000-packages-6.12/releases/download/firmware-redmi-ax6000-612-latest-a99b0888b88f-0b1249707848/SHA256SUMS) |

Factory UBI, FIT для RAM и sysupgrade имеют разное назначение.
[Ручная проверка и выбор файла](docs/FLASH.md) обязательны перед установкой.
Не применять образы mtkuboot/ubootmod к stock и не менять загрузчик автоматически.

Штатная stock-разметка выделяет **80 MiB** под UBI root. Официальный
Tailscale 1.104.2-r2 занимает около **69,2 MiB после распаковки**, поэтому
не помещается в оставшийся штатный overlay. Доступность IPK не означает,
что его можно установить на stock. Разметка ubootmod имеет UBI около
**122,5 MiB**, но переход на неё — отдельная ручная процедура владельца,
а не рекомендация менять разметку ради пакета. Фактическое свободное место
нужно проверять на устройстве; аппаратные испытания здесь не выполнялись.

## Точные SDK и проверки

| Линия | Kernel ABI | SDK SHA256 |
| --- | --- | --- |
| recommended | `6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1` | `6ef19743b104b7f2de0c3d3dffb91b3b782222cc60184ea0cc294fa653d39426` |
| latest | `6.12.112~d405163bfdb42254c245797a894994c0-r1` | `0b124970784803d24235d999ba77862919f651496283f4b865264bbebd575fbd` |

Recommended build ID:
`redmi-ax6000-612-recommended-ae65e1de6997-6ef19743b104`.
Latest build ID: `redmi-ax6000-612-latest-a99b0888b88f-0b1249707848`.

Проверены нативные образы и исключение Tailscale из rootfs/initramfs.
Нативные сборки, отдельные SDK и первичные публикации проверены:

- Recommended: 1389 нативных IPK, включая 1079 пакетов kmod; SDK-прогон дал 1386 IPK: 224 пакета собраны заново, включая AmneziaWG; все 1078 штатных kmod сохранены побайтно;
  при первичной публикации проверены 1384 предлагаемых IPK, 1397 файлов канала и все 18 внешних артефактов Release.
- Latest: 1389 нативных IPK, включая 1079 пакетов kmod; SDK-прогон дал 1386 IPK: 224 пакета собраны заново, включая AmneziaWG; все 1078 штатных kmod сохранены побайтно;
  при первичной публикации проверены 1384 предлагаемых IPK, 1397 файлов канала и все 18 внешних артефактов Release.
- Побайтное сохранение другого канала при замене поколения:
  обе последовательные миграции сохранили подписанный указатель, каждый файл и все внешние артефакты другого канала.

Эти проверки подтверждают состав и целостность артефактов, а не загрузку,
производительность, работу Wi-Fi или HNAT на физическом роутере.
Vendor-стек выбранного форка сохранён в конфигурации сборки.
Банк модулей включает альтернативные драйверы; их наличие в feed не означает,
что их следует устанавливать вместе с работающим vendor-стеком.

## Подключение пакетов

После ручной установки совпадающей прошивки проверить сеть и выполнить
**на роутере от root**:

```sh
opkg status kernel
ax6000-install-feed
```

Встроенная команда проверяет точный ABI, архитектуру, закреплённый ключ
и подпись индекса; сохраняет конфигурацию opkg и подключает feed своей линии.
Другие активные feeds отключаются. Пакеты, включая Tailscale, не устанавливаются.
Модули разных линий и Linux 6.6 несовместимы; не подменять зависимость `kernel`.

## Ежедневные обновления

База прошивки и штатные модули закреплены. Новые запрошенные пакеты и AmneziaWG
собираются из SDK своего канала. Каналы обрабатываются последовательно;
канал без успешного обновления сохраняется побайтно. Сбой сборки или проверки
не разрешает автоматическую замену поколения прошивки.

Проверка **новых SDK обеих линий**: [контрольный прогон](https://github.com/valujin/ax6000-packages-6.12/actions/runs/39544015510) —
оба канала обновлены из новых SDK; в каждом проверены 1384 IPK,
1078 побайтно сохранённых штатных kmod, 1395 файлов канала и все 18
внешних артефактов прошивки/SDK. Проверено точное совпадение официальных
бинарных файлов Tailscale 1.104.2. Предыдущие прогоны относятся к прежним SDK.

Активные профили — `profiles/redmi-ax6000-612-recommended.json` и
`profiles/redmi-ax6000-612-latest.json`; `*-new.json` описывают полную сборку.
Прежние неизменяемые Releases
[recommended](https://github.com/valujin/ax6000-packages-6.12/releases/tag/firmware-redmi-ax6000-612-recommended-ae65e1de6997-96f60860edff)
и [latest](https://github.com/valujin/ax6000-packages-6.12/releases/tag/firmware-redmi-ax6000-612-latest-a99b0888b88f-30f1cc518a7f)
сохранены; старые SDK и файлы не перезаписываются.

[CI и подпись](docs/CI.md) · [Локальная сборка](docs/BUILD.md) ·
[Проверка установки](docs/FLASH.md) · [Удалённый испытательный стенд](docs/TESTBENCH.md) ·
[Драйверы 6.12](docs/KERNEL-6.12.md).
Linux 6.18 отложен до появления полного vendor-порта для AX6000.
