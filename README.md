# lpac-multibox

Мультибокс для Windows-игр через Sandboxie.

## Файлы

- `multibox.cpp` → `multibox.exe` (управление запуском)
- `isolate.cpp` → `isolate.dll` (хуки синхронизации)
---

## Сборка

### 1) Сборка DLL

```bash
g++ -shared -O2 -o isolate.dll isolate.cpp -lntdll -static-libgcc -static-libstdc++
```

### 2) Сборка EXE

```bash
g++ -O2 -std=c++17 -o multibox.exe multibox.cpp -ladvapi32 -lshell32 -static-libgcc -static-libstdc++
```

---

## Требования

- Windows x64
- Sandboxie-Plus (`C:\Program Files\Sandboxie-Plus\Start.exe`)
- MinGW-w64

---

## Параметры `multibox.exe`

| Параметр | Описание |
|---|---|
| `--instances N` | Количество экземпляров (1..20) |
| `--game-dir PATH` | Папка игры (**обязательно**) |
| `--game-exe NAME` | Имя exe игры (по умолчанию `GenshinImpact.exe`) |
| `--launcher PATH` | Путь к лаунчеру (**обязательно**) |
| `--dll PATH` | Путь к `isolate.dll` (если не задан, берётся рядом с `multibox.exe`) |
| `--sb-path PATH` | Путь к Sandboxie `Start.exe` |
| `--args "..."` | Доп. аргументы для лаунчера |
| `--launcher-delay MS` | Пауза после старта лаунчера |
| `--pair-delay MS` | Пауза между парами запуска |
| `--auto` | Автоматический режим без ENTER |
| `--auto-delay MS` | Задержка авто-старта игры (включает `--auto`) |
| `--no-copy` | Не создавать копии файлов конфигов |
| `--box NAME` | Имя Sandboxie-бокса (можно указывать несколько раз) |

Если `--box` указано меньше, чем `--instances`, недостающие имена генерируются как `Box0`, `Box1`, ...

---

## Настройка Sandboxie

Для каждого бокса в `Sandboxie.ini` должны быть строки:

```ini
[Box0]
InjectDll=D:\Tools\lpac\isolate.dll
SetEnvironmentVariable=MULTIBOX_JOB_ID=0

[Box1]
InjectDll=D:\Tools\lpac\isolate.dll
SetEnvironmentVariable=MULTIBOX_JOB_ID=1
```

Важно:
- `InjectDll` должен указывать на корректный путь к вашей `isolate.dll`;
- `MULTIBOX_JOB_ID` должен соответствовать индексу экземпляра;
- имена секций (`[Box0]`, `[Box1]`) должны совпадать с `--box`.

---

## Как работает

Для каждого экземпляра:

1. Стартует лаунчер(Не лаунчер в проекте, а лаунчер, который внедряется в игру).
2. В лаунчер инжектится `isolate.dll`.
3. Вы нажимаете Инжект.
4. Игра стартует через Sandboxie в нужном боксе.
5. `multibox.exe` находит PID игры и пишет `%TEMP%\multibox_game_pid_<ID>.tmp`.
6. `isolate.dll` использует этот PID для корректной фильтрации.


---

## Стек

- **C++17** 
- **WinAPI**
- **NT API**