Упрощение подготовки миграции пользователей.

## Файлы

| Файл | Что делает |
|---|---|
| `step1_precheck.py` | Шаг 1. Проверки: активные юниты, коннекты, DB links, cross-segment параметры; создаёт мониторинговые вьюхи (SYSTEM). |
| `step2_precopy.py`  | Шаг 2. Добавляет пользователей в `zadmin.vscheduled_users`, запускает `0.1_pre-copy_session_create.sql`, `0.2_pre-copylogs.sql` и `2.0_copylogs.sql` по каждой transfer-сессии. |
| `config.ini`        | Настройки (юниты source/target, путь к релизу, VIP-код, файл пользователей). |
| `users_to_move.txt` | Список userid для миграции (через пробел, запятую или с новой строки). |

## Запуск

```bash
export UMOVE_USER=umove
export UMOVE_PASS='****'
export SYSTEM_PASS='****'

python3 step1_precheck.py config.ini
python3 step2_precopy.py  config.ini
```

Логи каждого запуска — в отдельной папке `logs/<дата_время>_<скрипт>/`, файлы пронумерованы
по порядку действий: `01_romode_PRO-ADB251.log`, `02_romode_PRO-ADB252.log`, ...

## config.ini

Минимально: `[db] source_db_units / target_db_units`, `[paths] release_root`,
`[prep] vip_code_name / users_file`. Активные юниты, DB links (PRO-ADB252 -> ADB252),
номера POD (читаются из базы) и все каталоги определяются автоматически и печатаются при запуске.
Явные значения (см. закомментированный блок в config.ini) нужны только для переопределения.
