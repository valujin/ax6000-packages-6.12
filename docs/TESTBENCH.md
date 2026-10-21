# AX6000: стенд для удалённых испытаний без нажатия кнопок

21 октября 2026. Рекомендация по исходникам и документации; реальный роутер не подключался и recovery на нём не испытывался. 

Для первого испытания сохраняем **stock**, соответствующий текущему `xiaomi,redmi-router-ax6000-stock`. Для последующего выделенного стенда мой кандидат — **`xiaomi_redmi-router-ax6000-ubootmod` с OpenWrt U-Boot 2025.10 из нашей закреплённой сборки**, после организации независимых UART, питания и Ethernet/TFTP. Это выбор архитектуры стенда по исходникам; аппаратная приёмка ещё требуется. Одна смена layout не обеспечивает восстановление без человека. Сам `board_name=...stock` определяет разметку, но не доказывает, что установлен именно оригинальный Xiaomi U-Boot.

## Почему этот вариант

| Вариант | Возможность | Ограничение для удалённого стенда |
|---|---|---|
| stock + оригинальный Xiaomi загрузчик | Обычное обновление через SSH/sysupgrade; штатные UART/TFTP способы восстановления | Recovery-вход может требовать RESET при подаче питания; текущий stock upgrade фиксирует boot flags, это не готовая A/B схема отката |
| MTK U-Boot / hanwckf, AX6000 `immortalwrt-110m` | Failsafe WebUI и serial; наш `mtkuboot` соответствует 110 MiB | Документированный вход в WebUI использует удержание RESET; нужный FIP — отдельный вариант, не OpenWrt ubootmod |
| OpenWrt `ubootmod`, наш U-Boot 2025.10 | Раздельные production/recovery UBI volumes, TFTP fallback, доступный serial, собираемый netconsole | Не распознаёт произвольную потерю сети/зависание уже запущенного Linux; отдельный recovery volume надо действительно подготовить |

[Штатная инструкция AX6000](https://openwrt.org/toh/xiaomi/redmi_ax6000) описывает stock/OEM recovery и UART 115200 8N1, 3.3 V. [Документация автора hanwckf](https://cmi.hanwckf.top/p/mt798x-uboot-usage/#failsafe-webui%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E) описывает RESET/WebUI; его [матрица AX6000](https://github.com/hanwckf/bl-mt798x#redmi-ax6000-multi-layout-uboot-firmware-compatibility) явно различает default, 110m и несовместимый с ними OpenWrt ubootmod. Перенос между ними затрагивает загрузчик/разметку, а не только очередной sysupgrade.

## Что подтверждено именно для наших исходников

Проверены рекомендованный [`ae65e1de6997`](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/tree/ae65e1de69971b5a2e3cf7e39390ee93f274d488) и latest [`a99b0888b88f`](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/tree/a99b0888b88f134f56bcb2a7d93027b5d20638a9): U-Boot recipe, AX6000 patch, pstore patches и ubootmod DTS побайтово одинаковы. [Recipe](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/ae65e1de69971b5a2e3cf7e39390ee93f274d488/package/boot/uboot-mediatek/Makefile) выбирает U-Boot 2025.10, config `mt7986_xiaomi_redmi-ax6000`, TF-A MT7986 SPI-NAND DDR4. [Image profile](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/ae65e1de69971b5a2e3cf7e39390ee93f274d488/target/linux/mediatek/image/filogic.mk) связывает его с `-ubootmod-preloader.bin`, `-ubootmod-bl31-uboot.fip`, recovery `.itb` и sysupgrade `.itb`. Это точный кандидат для будущего стенда, а не рекомендация случайного стороннего бинарника.

В [AX6000 default environment](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/ae65e1de69971b5a2e3cf7e39390ee93f274d488/package/boot/uboot-mediatek/patches/431-add-xiaomi_redmi-ax6000.patch) действительно предусмотрены production → recovery → TFTP и отдельный путь через pstore. TFTP ожидается от `192.168.1.254`, загрузчик использует `192.168.1.1`; имя файла именно `immortalwrt-mediatek-filogic-xiaomi_redmi-router-ax6000-ubootmod-initramfs-recovery.itb`. Наличие файла в релизе ещё не означает наличие записанного NAND volume `recovery`: его подготовка отдельно предусмотрена [первичным OpenWrt commit/instructions](https://lists.infradead.org/pipermail/lede-commits/2022-December/016842.html).

Проверен и **фактически собранный recommended U-Boot `.config`**: `NETCONSOLE=y`, а `BOOTCOUNT_LIMIT`, `BOOT_RETRY`, U-Boot `WATCHDOG` выключены. Default environment не включает ввод/вывод netconsole. Это проверка сборки и её исходников, не установленного на роутере загрузчика. Текущий REC recovery `.itb` занимает **16 318 464 байта**: старый пример с volume 10 MiB ему не подходит; размер recovery надо выбирать по фактическому файлу и доступным UBI LEB.

## Где заканчивается автоматическое восстановление

Ошибка чтения/проверки FIT, при которой управление возвращается U-Boot, позволяет перейти к recovery/TFTP. Валидный образ, который передал управление Linux и затем завис либо загрузился с неверной сетью, — другой случай: строки fallback уже не исполняются. Обычный power-cycle снова может загрузить тот же неисправный production.

pstore-путь проверяет crash-запись, а не успешный SSH, Ethernet или доступ в Интернет. [Реализация проверки](https://github.com/chasey-dev/immortalwrt-mt798x-rebase/blob/ae65e1de69971b5a2e3cf7e39390ee93f274d488/package/boot/uboot-mediatek/patches/230-cmd-add-pstore-check.patch) ищет валидные сохранённые kernel records. [Ramoops](https://www.kernel.org/doc/html/latest/admin-guide/ramoops.html) зависит от сохранности RAM после reset; на это нельзя рассчитывать после полного отключения питания. Успех этого пути после panic/watchdog на нашем железе ещё нужно проверить.

Полноценный trial-boot/rollback потребовал бы отдельно настроенных счётчика, альтернативной загрузки и userspace health acknowledgement: [контракт U-Boot Boot Count Limit](https://docs.u-boot.org/en/v2025.10/api/bootcount.html). В исследованной сборке такого контура нет. Настроенный [U-Boot netconsole](https://docs.u-boot.org/en/v2025.10/usage/netconsole.html) может дать дополнительный сетевой доступ до Linux, но требует заранее работающих bootloader Ethernet, `ncip` и console routing; один `CONFIG_NETCONSOLE=y` этого не доказывает.

## Практический следующий шаг

1. Оставить текущую разметку. При следующем разрешённом подключении только прочитать board/MTD/boot environment и снять serial boot log, чтобы определить настоящий загрузчик и окно остановки. Сохранить вне роутера дампы BL2/NVRAM/Bdata/Factory/FIP и проверенный stock recovery-образ. Номера MTD брать с конкретного устройства.
2. Организовать постоянно доступный независимый Linux-хост рядом с роутером: UART USB/serial server, Ethernet в подтверждённый LAN-порт, TFTP и управление питанием AX6000. Доступ к этому хосту и питанию должен переживать поломку тестируемого роутера; Tailscale/VPN только на самом AX6000 для этого недостаточно. UART-проводка — уровни 3.3 V, TX/RX/GND, без питания роутера от VCC адаптера.
3. Сначала подтвердить при локальном сопровождении: passive boot log, удалённый power-cycle, остановку U-Boot и загрузку корректного initramfs **в RAM** через пункт `Boot system via TFTP`. Это приёмка канала восстановления; после неё повторные тесты могут обходиться без кнопок. UART особенно полезен для анализа до и после запуска ядра. BootROM UART-инструмент [mtk_uartboot](https://github.com/981213/mtk_uartboot) — дополнительный путь для MT798x при отключённом secure boot; готовность именно нашего AX6000 к нему пока не проверена.
4. Если нужен выделенный многократный стенд, после этой приёмки отдельно планировать переход на точный `ubootmod` и установку заведомо исправного recovery. Контроллер должен после таймаута выбирать проверенный recovery через независимую консоль, а не бесконечно перезагружать неисправную прошивку. Испытание recovery и его RAM-копии должно предшествовать первой unattended записи production.

Без UART/проверенного bootloader netconsole и независимого управления питанием можно автоматизировать штатное SSH-обновление и проверку успешной загрузки. Обещать восстановление после любой неудачи в такой конфигурации оснований нет. Здесь не выполнялись прошивка, запись env, переключение layout, доступ к устройству или изменение сервисов сервера.
