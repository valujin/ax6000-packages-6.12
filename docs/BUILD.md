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
GitHub Actions использует только hosted runners; автоматического переноса
полной сборки на сервер нет.
