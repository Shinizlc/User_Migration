Упрощение подготовки миграции пользователей.
Перед запуском нужно задать переменные окружения:
-- export UMOVE_USER=umove;
-- export UMOVE_PASS='****';
-- export SYSTEM_PASS='****';

Минимальный config.ini: `[db] source_db_units / target_db_units`, `[paths] release_root`,
`[prep] vip_code_name / users_file`. Активные юниты, DB links (PRO-ADB252 -> ADB252),
номера POD (ADB25x -> 25) и все каталоги вычисляются автоматически и печатаются при запуске.
Явные значения (см. закомментированный блок в config.ini) нужны только для переопределения.
