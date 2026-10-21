# Linux 6.12 и драйверы MediaTek для Redmi AX6000

Проверено 12 октября 2026 года. Исследование выполнено отдельно от текущей сборки Linux 6.6; её исходники, настройки и задания не изменялись.

**Да: публичный порт фирменного стека `mt_wifi` для MT7986 и Linux 6.12 существует.** Найдены исходники, адаптация API ядра, конфигурация Redmi AX6000, опубликованные образы с проверяемым составом и журнал реально работающего AX6000. Однако для **stock layout именно этого роутера** найден профиль сборки, но не независимое подтверждение загрузки и производительности. Последняя ревизия порта содержит свежую регрессию HNAT, поэтому автоматически менять текущую сборку на неё нельзя.

## Какое ядро сейчас актуально

Стабильная серия OpenWrt — 25.12; официальный сайт указывает последний релиз 25.12.5. Проверка исходников тега подтверждает для MediaTek Linux **6.12.94**, а текущая ветка `openwrt-25.12` содержит **6.12.112**. Ветка разработки `main` уже использует для MediaTek **6.18**. Следовательно, 6.12 — актуальная стабильная линия OpenWrt, а не самое новое ядро вообще. Источники: [серия 25.12](https://openwrt.org/releases/25.12/start), [MediaTek в v25.12.5](https://github.com/openwrt/openwrt/blob/v25.12.5/target/linux/mediatek/Makefile), [версия ядра v25.12.5](https://github.com/openwrt/openwrt/blob/v25.12.5/target/linux/generic/kernel-6.12), [стабильная ветка](https://github.com/openwrt/openwrt/blob/openwrt-25.12/target/linux/generic/kernel-6.12), [MediaTek main](https://github.com/openwrt/openwrt/blob/main/target/linux/mediatek/Makefile).

## Найденный порт и уровень подтверждения

Основной кандидат — [chasey-dev/immortalwrt-mt798x-rebase, ветка 25.12](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/tree/25.12). Это ImmortalWrt с импортированными изменениями MTK OpenWrt Feeds и отдельным фирменным стеком Wi-Fi 6. Проверенная текущая ревизия: `a99b0888b88f134f56bcb2a7d93027b5d20638a9`, 10 октября 2026 года.

| Что проверено | Результат и граница доказательства |
|---|---|
| Целевая версия ядра | `KERNEL_PATCHVER:=6.12`; текущий патч-релиз 6.12.112 |
| Фирменный Wi-Fi | Пакет `kmod-mt_wifi`, драйвер 7.6.7.3, MT7986; это другой стек, чем `mt76` |
| Сопутствующие модули | `kmod-conninfra`, `kmod-warp`, `kmod-mediatek_hnat` |
| Redmi AX6000 stock | Есть DTS, совместимый идентификатор `xiaomi,redmi-router-ax6000-stock` и профиль `sysupgrade.bin` |
| Реальная сборка AX6000 | Найден опубликованный образ с Linux 6.12.108 и всеми четырьмя модулями; его разметка — MTK U-Boot 110 MiB |
| Реальная загрузка AX6000 | Найден журнал Linux 6.12.94 с загруженными `mt_wifi`, WARP, HNAT; его разметка — OpenWrt U-Boot |
| Реальная загрузка stock | В исследованных первичных источниках не подтверждена |
| Сравнение скорости с нашей 6.6 | Контролируемого теста на AX6000 с одинаковыми настройками не найдено |

Версии ядра подтверждают [Makefile MediaTek](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/target/linux/mediatek/Makefile) и [kernel-6.12](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/target/linux/generic/kernel-6.12). Профиль AX6000 подтверждается [defconfig](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/defconfig/mt7986-ax6000.config) и [DTS stock](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/target/linux/mediatek/dts/mt7986a-xiaomi-redmi-router-ax6000-stock.dts).

## Из чего состоит фирменный стек

| Компонент | Проверенная версия/роль | Первичный источник |
|---|---|---|
| `mt_wifi` | По умолчанию 7.6.7.3; архив `mt79xx_20250408-705eb4.tar.xz`; поддержка MT7986 | [Makefile](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/package/mtk/drivers/mt_wifi/Makefile) |
| Wi-Fi firmware | AX6000 defconfig выбирает `mt7986-fw-20260601`; доступны также более ранние варианты | [выбор firmware](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/package/mtk/drivers/mt_wifi/config.in) |
| `conninfra` | 20231229, инфраструктура MT7986/MT7981 | [Makefile](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/package/mtk/drivers/conninfra/Makefile) |
| WARP | 20250408, конфигурация WARP v2 для MT7986, firmware WOCPU | [Makefile](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/package/mtk/drivers/warp/Makefile) |
| HNAT | Vendor-путь аппаратного ускорения, исходники внутри дерева ядра 6.12 | [HNAT](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/tree/a99b0888b88f134f56bcb2a7d93027b5d20638a9/target/linux/mediatek/files-6.12/drivers/net/ethernet/mediatek/mtk_hnat) |
| Настройка Wi-Fi | `mtwifi-cfg-ucode` 3 вместо прежней Lua-реализации; интеграция с wifi-scripts и iwinfo-ucode | [Makefile управления](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/package/mtk/applications/mtwifi-cfg-ucode/Makefile) |

Термин «закрытые драйверы» здесь требует точности. Архив `mt_wifi` действительно опубликован: при проверке он содержит 381 файл C, 551 заголовок и ни одного `.o`, `.a` или `.ko`. Модуль собирается из опубликованного фирменного C-кода; этот код имеет ограничительные MediaTek-заголовки и объявляет `MODULE_LICENSE("Proprietary")`. Дополнительно используются бинарные firmware-файлы. Это не просто готовый бинарный `.ko` с открытой обёрткой и не полностью свободный стек. Архив скачан без распаковки в исходное дерево; SHA256 совпал с рецептом: `b029d7b43c498193092dc6a3c857361c8835ce34bb306561c550ac0539784a78`. [Архив производителя в hanwckf/dl](https://github.com/hanwckf/immortalwrt-mt798x/blob/openwrt-21.02/dl/mt79xx_20250408-705eb4.tar.xz).

При этом HNAT нельзя автоматически называть закрытым: его опубликованный файл `hnat.c` содержит GPL v2 и `MODULE_LICENSE("GPL v2")`. У остальных частей стека лицензии также различаются. [Официальный MediaTek HNAT 6.12](https://github.com/mediatek/mtk-openwrt-feeds/blob/main/autobuild/unified/global/logan_common/25.12/files/target/linux/mediatek/files-6.12/drivers/net/ethernet/mediatek/mtk_hnat/hnat.c).

Есть реальные патчи перехода на новые API: `asm/unaligned.h` заменяется на `linux/unaligned.h` для 6.12, исправлены `strlcpy`, отсутствующие прототипы, callback `platform_driver.remove` после 6.11 и другие изменения. Это подтверждает целевой порт, а не случайную строку версии: [патч mt_wifi 6.12](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/package/mtk/drivers/mt_wifi/patches-7673/034-since-v6.12-fix-unaligned_h-not-found-error.patch), [патч conninfra](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/package/mtk/drivers/conninfra/patches/007-since-v6.11-fix-platform_driver-expect-void-in-remove-callback.patch), [патчи WARP](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/tree/a99b0888b88f134f56bcb2a7d93027b5d20638a9/package/mtk/drivers/warp/patches).

## Сборки и фактическая работа на AX6000

В [релизе saltdion от 8 октября](https://github.com/saltdion/immortalwrt-mt798x-rebase/releases/tag/ax6000-mtk-25.12-ae65e1de6997-88b0db0057c6) опубликованы AX6000 initramfs/factory/sysupgrade и manifest. Прочитанный manifest содержит:

```text
kernel - 6.12.108~7cd4d2c5ee4852cbd8d02c58a20e9ded-r1
kmod-conninfra - 6.12.108.20231229-r1
kmod-mediatek_hnat - 6.12.108-r1
kmod-mt_wifi - 6.12.108.7.6.7.3-r1
kmod-warp - 6.12.108.20250408-r1
apk-openssl - 3.0.5-r3
```

Manifest проверен непосредственно как release asset. Его разметка — **`xiaomi_redmi-router-ax6000-mtkuboot`**, 110 MiB, поэтому он не предназначен для нашего `stock`. Автор отдельно указывает, что успешная компиляция не доказывает испытания на железе. Независимый [Cyrusjy build](https://github.com/Cyrusjy/ax6000-builder/releases/tag/ax6000-20261010-ae65e1d) также опубликовал образ на той же ревизии и разметке. В [рецепте Cyrusjy](https://github.com/Cyrusjy/ax6000-builder) stock доступен как вариант ручного задания, но наличие варианта не доказывает выполненную stock-сборку.

Более сильное доказательство загрузки — [issue #94](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/issues/94). Журнал с Redmi AX6000 показывает Linux 6.12.94, загруженные `mt_wifi(PO)`, `mtk_warp_proxy(PO)`, `mtk_warp`, `mtkhnat`, `conninfra` и обмен WPA3. Однако там **OpenWrt U-Boot layout**, а сам отчёт посвящён падению драйвера после WPA3-handshake. Issue закрыта; в проверенной более поздней ревизии присутствует исправление этого пути RX: [патч 041](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/ae65e1de69971b5a2e3cf7e39390ee93f274d488/package/mtk/drivers/mt_wifi/patches-7673/041-fix-cmm_data-header-translated-port-security.patch). Это подтверждает работу и конкретное устранение ошибки, но не все режимы и клиенты Wi-Fi.

В исходниках stock сохранён отдельный DTS с `ubi_kernel` от `0x600000`, `ubi` от `0x2400000` и фирменным идентификатором. Общий DTS AX6000 содержит `mediatek,mtd-eeprom = <&factory 0x0>`. Для него используется собственный профиль AX6000 и firmware MT7986. Нельзя подменять его готовым образом 110 MiB или `ubootmod`: [stock DTS](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/target/linux/mediatek/dts/mt7986a-xiaomi-redmi-router-ax6000-stock.dts), [общий DTS](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/ae65e1de69971b5a2e3cf7e39390ee93f274d488/target/linux/mediatek/dts/mt7986a-xiaomi-redmi-router-ax6000.dtsi), [правила image](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/a99b0888b88f134f56bcb2a7d93027b5d20638a9/target/linux/mediatek/image/filogic.mk).

## Почему последнее состояние ветки нельзя считать стабильной базой

11 октября сопровождающий открыл [#112: регрессия HNAT после merge 10 октября](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/issues/112) и рекомендует более ранний snapshot до исправления. Пользователь подтвердил высокую загрузку CPU при связанных PPE flows. Указанная ревизия — `a99b088...`, устройство Cudy TR3000. Это другая модель, но общий стек; эффект на AX6000 пока неизвестен.

Также [#113](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/issues/113) содержит panic на OpenFi 6C/MT7981 с 6.12.112 при чтении HNAT debugfs entry table. В его журнале аппаратное ускорение USB-WAN работало, однако это не тест AX6000. Название «closed-source mtkhnat» в этом issue не совпадает с лицензией опубликованного HNAT-кода и здесь не принимается как доказательство лицензирования.

Для отдельной пробной сборки наиболее обоснован **кандидат**, а не обещанная стабильная версия: `ae65e1de69971b5a2e3cf7e39390ee93f274d488` от 6 октября, Linux 6.12.108. Он предшествует проблемному merge, уже содержит исправление #94 и имеет две независимые опубликованные AX6000-сборки. [Зафиксированный commit](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/commit/ae65e1de69971b5a2e3cf7e39390ee93f274d488), [его версия ядра](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/ae65e1de69971b5a2e3cf7e39390ee93f274d488/target/linux/generic/kernel-6.12). Он не сертифицирован как стабильный stock-образ; выбирать его окончательно можно только после проверки необходимых последующих исправлений и испытаний.

Оставшиеся ограничения: [#87 — аппаратный QoS/bufferbloat на AX3000T](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/issues/87), [предупреждение автора о неполных испытаниях external-device HNAT](https://github.com/chasey-dev/immortalwrt-mt798x-rebase#about-external-devices-hnat). Отчёты других моделей нельзя переносить на AX6000 как готовый результат скорости.

Сопровождающий отдельно объясняет, что vendor `mt_wifi` работает с `mtk_hnat`, а `mt76` — с `mtk_ppe`; одновременный доступ двух реализаций к PPE может вызывать падения. Поэтому штатные переключатели `flow_offloading_hw` нельзя просто включать вместе с HNAT. [Объяснение в #35](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/issues/35).

## APK, opkg и наш репозиторий пакетов

Новые поколения обеих линий 6.12 явно используют **APK v3**. Реализованы
сборка из точного SDK, подписанный `packages.adb`, проверка APK, отдельный
ключ и установщик feed. Прежние опубликованные OPKG/IPK-поколения
сохраняются отдельно до принятия новых сборок; они не превращаются в APK
от обновления индекса. Формат и SDK всегда проверять по `profile.json`
конкретного Release.

Публичные userspace-feeds новой прошивки — полный доступный набор одной
ImmortalWrt 25.12.0 с тегом `@public`; ядро, vendor-стек и защищённые
нативные зависимости закреплены. ASU может использовать отдельно
проверенный набор одной OpenWrt 25.12.0, но не смешивает дистрибуции.
Официальные индексы ASU фиксируются по подписи и SHA256, а не обновляются
при каждом запросе устройства.

В исходном fork путь OPKG/IPK ещё существует через отключение `USE_APK`,
но это историческая совместимость старых поколений, а не выбранный
формат новых сборок. Переход OPKG → APK выполняется установкой новой
прошивки владельцем. SDK и модули 6.6 несовместимы с 6.12 независимо
от общей ARM64-архитектуры; зависимости `kernel` не переписываются.

В нашем recommended закреплённые исходники `ae65e1de6997` выбирают
`mt_wifi 7.6.7.3` через `CONFIG_MTK_MT_WIFI_DRIVER_VERSION_7673=y`;
это подтверждено конфигурацией нативной сборки, а не только сторонним
manifest. Версия нового артефакта latest проверяется отдельно; до
завершения проверки переносить на него результат recommended нельзя.
Состав и готовность опубликованного набора указаны в [README](../README.md).

## Практический маршрут миграции

1. Создать отдельный профиль/выходной каталог 6.12 и зафиксировать исходный commit и каждый feed. Сначала использовать полный `defconfig/mt7986-ax6000.config`, затем оставить только **stock**-device и необходимые пакеты. Не переносить старую `.config` целиком: она не описывает новую цепочку ucode Wi-Fi.
2. Сохранить четыре vendor-модуля, MT7986 firmware/EEPROM/SKU и соответствующие utilities. Собрать новую прошивку, SDK и весь набор выбранных kmods в одном контексте. Отдельный новый feed должен проверять полученный kernel ABI.
3. Для нового поколения выбрать APK явно и проверить соответствующий SDK, подпись и установщик. Старый OPKG feed оставить в его прежнем поколении; не использовать SDK/модули 6.6 и не переписывать опубликованный каталог.
4. До установки сверить board ID, stock-разметку, metadata образа и размер разделов. Само исследование не требует изменения U-Boot. Готовые сторонние 110 MiB-образы служат доказательством компиляции, а не образом для нашего роутера.
5. На реальном AX6000 проверить Ethernet, оба диапазона Wi-Fi, WPA2/WPA3, переподключения, HNAT, PBR и VPN-маршруты. Сравнить iperf3 WAN/LAN/Wi-Fi, CPU, задержки и стабильность под одинаковой нагрузкой с 6.6. Только после этого решать, заменять ли основную линию.

## Что ещё проверялось

Поиск включал английские и китайские запросы `mt_wifi 6.12`, `MT7986 6.12`, `闭源`, Redmi/AX6000/stock; GitHub поиск кода и issues, список веток padavanonly/hanwckf, дерево официального MTK feed, fork/release-метаданные и реальные manifest-файлы.

У [padavanonly](https://github.com/padavanonly/immortalwrt-mt798x-6.6) не обнаружен собственный публичный successor-repo 6.12; [hanwckf](https://github.com/hanwckf/immortalwrt-mt798x) остаётся источником vendor-архивов с веткой 21.02. Найденные [tfnhui сборки](https://github.com/tfnhui/immortalwrt-mt798x-25.12/releases) относятся к RAX3000M, поэтому не доказывают поддержку AX6000 stock.

Официальный MediaTek имеет 6.12 platform/HNAT-исходники, но найденная [документация Readme-6.12](https://github.com/mediatek/mtk-openwrt-feeds/blob/main/autobuild/unified/Readme-6.12.md) описывает **SoftMAC MT76 Wi-Fi 7** и MT7987/MT7988, а [platform user guide](https://github.com/mediatek/mtk-openwrt-feeds/blob/main/autobuild/unified/doc/MediaTek_OpenWrt_2512_User_Guide.md) прямо исключает Wi-Fi. Ни один из этих документов сам по себе не доказывает vendor Wi-Fi 6 для AX6000; положительный вывод выше основан на проверенном community-порте и его артефактах.
