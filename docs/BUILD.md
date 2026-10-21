# Ограниченная локальная сборка

Полная сборка выполняется в отдельном Docker-контейнере. Пакеты сборочной
системы устанавливаются только внутри контейнера; исходный checkout 6.6 и
сервисы хоста не изменяются. Для сервера 8 CPU / 23 GiB установлены лимиты
4 CPU, 10 GiB RAM, без swap, nice 19 и idle I/O. Тяжёлые сборки выполняются
последовательно, включая сборки другого репозитория.

Для воспроизводимого запуска использовать отдельный чистый checkout рецептов
на закреплённом commit. Выбрать `recommended` или `latest`, разрешить lock
свежих пакетов, проверить pins и сохранить его до начала сборки:

```sh
channel=recommended
mkdir -p state ../ax6000-packages-6.12-build/$channel/{work,output} ../ax6000-build-global
python3 scripts/monitor.py --profile "profiles/redmi-ax6000-612-$channel-new.json" \
  --output "state/$channel-new-lock.json"
python3 - "profiles/redmi-ax6000-612-$channel-new.json" "state/$channel-new-lock.json" <<'PY'
import json
from pathlib import Path
import sys
profile = json.loads(Path(sys.argv[1]).read_text())
path = Path(sys.argv[2])
lock = json.loads(path.read_text())
lock['feeds'] = {feed['name']: feed['commit'] for feed in profile['feeds']}
path.write_text(json.dumps(lock, indent=2, sort_keys=True) + '\n')
PY
docker run -d --name "ax6000-612-$channel-build" \
  --cpus 4 --memory 10g --memory-swap 10g --pids-limit 2048 \
  --oom-score-adj 500 --security-opt no-new-privileges \
  --mount "type=bind,src=$PWD,dst=/workspace,readonly" \
  --mount "type=bind,src=$(realpath ../ax6000-packages-6.12-build/$channel/work),dst=/build" \
  --mount "type=bind,src=$(realpath ../ax6000-packages-6.12-build/$channel/output),dst=/output" \
  --mount "type=bind,src=$(realpath ../ax6000-build-global),dst=/global" \
  ubuntu:24.04 bash /workspace/scripts/container-entrypoint.sh \
  --profile "/workspace/profiles/redmi-ax6000-612-$channel-new.json" \
  --lock "/workspace/state/$channel-new-lock.json" --work-dir /build --output-dir /output/raw
```

Полная сборка сохраняет проверенные commits feeds из профиля. Ежедневные
SDK-сборки разрешают свежие версии пакетов отдельно.

Все другие локальные сборки должны использовать тот же файл lock:
`AX6000_BUILD_LOCK=/absolute/path/ax6000-build-global/.build.lock`
(в контейнерах — bind mount того же файла). Скрипт откажется запускать вторую
сборку, пока первая удерживает lock. Контейнер ограничивает память всего дерева
процессов, а `resource-limit.sh` дополнительно ограничивает affinity и jobs.

Результат включает три разметки, точный SDK, IPK и provenance. Перед публикацией
проверить реальные образы:

```sh
python3 scripts/verify-firmware.py --source /absolute/source \
  --raw /absolute/output/raw --repo "$PWD" --output /absolute/verification.json
```

Экспортированный SDK отдельно проверяется сборкой свежих пакетов и AmneziaWG.
Штатные kmods остаются побайтно из исходной прошивки; её kernel context не
изменяется. Проверки артефактов не подтверждают загрузку на физическом роутере.
В новых source-профилях Tailscale остаётся отдельным IPK и исключён из образов.
Его обновления не требуют новой прошивки. Для отдельной установки большого
официального пакета проверять фактическое место в overlay: stock UBI 80 MiB
недостаточно для Tailscale 1.104.2-r2 с Installed-Size 72 519 680 байт
после размещения SquashFS. Для последующих испытаний доступен `ubootmod` с UBI
122.5 MiB; переход загрузчика и разметки выполняется владельцем отдельно.
GitHub Actions использует только hosted runners; автоматического переноса
полной сборки на сервер нет.
