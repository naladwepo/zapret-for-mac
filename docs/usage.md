# Как этим пользоваться

Задачи по порядку: первый запуск, подбор стратегии, «YouTube работает, Discord нет»,
голос в Discord, QUIC, конфликт с VPN, чтение предупреждений `zaprctl status`, полный
откат.

Команды и идентификаторы — на английском, потому что их надо копировать как есть.

## 0. Коды возврата

Полезно сразу, потому что на них удобно проверять, что вообще произошло:

| код | что значит |
|---|---|
| `0` | всё хорошо |
| `1` | ошибка: неверная команда, `doctor`/`test` нашли проблемы, `use` отказался переключаться без `--force` |
| `3` | демон не запущен (то, что можно было ответить локально, всё равно напечатано) |
| `4` | нет прав на control-сокет; в сообщении печатается точная команда с `sudo` |

```bash
zaprctl status; echo $?     # 3, пока демон не запущен
```

`doctor` — исключение: он и существует для того, чтобы сообщить «демон не работает»,
поэтому возвращает `1` (найдены проблемы), а не `3`.

## 1. Первый запуск

### 1.1. Сначала probe: что умеет именно эта машина

```bash
make build
sudo ./bin/zaprctl probe
```

Probe ничего не ломает: не пишет `/etc/pf.conf`, не меняет DNS и маршруты,
откатывает всё, что создал, и обращается только к одному адресу из RFC 5737.

* `full-parity-possible` — доступен транспорт **divert**: полный набор техник
  (`fake`, `seqovl`, UDP, TTL на пакет, `ip.id`).
* `proxy-only` — только транспорт **proxy**: TCP и байтовые трюки. Ни `fake`,
  ни `seqovl`, ни UDP. Работать будет, но большая часть стратегий flowseal
  потеряет свою главную технику.

Посмотреть, что именно теряется, можно **до установки** — демон для этого не нужен:

```bash
./bin/zaprctl list --transport proxy      # колонка NOT HONOURED заполнена честно
./bin/zaprctl caps --transport proxy      # матрица возможностей
./bin/zaprctl explain general --transport proxy
```

`multisplit(-seqovl)` в колонке NOT HONOURED означает: сама нарезка выполнится,
а перекрытие последовательности (то, ради чего стратегия и написана) — нет.

### 1.2. Установка и запуск

```bash
make install
zaprctl status
zaprctl list
sudo zaprctl use general
zaprctl test
```

Установка вручную, без `make`, и подробности про plist — в
[../packaging/README.md](../packaging/README.md).

`zaprctl test` открывает настоящие соединения с YouTube и Discord и показывает,
сработал ли desync (`DESYNC = fired`). Свои цели тоже можно:

```bash
zaprctl test www.youtube.com discord.com gateway.discord.gg:443
```

## 2. Подбор стратегии

Стратегию подбирают перебором. Это не недоделка: ТСПУ у разных провайдеров
разный и меняется, поэтому рабочая стратегия — локальный факт, а не константа.

```bash
zaprctl list                        # 21 стратегия, * = активная
sudo zaprctl use general-alt3
zaprctl test
```

Порядок как в оригинале flowseal: сначала добейтесь, чтобы работал YouTube,
и только потом проверяйте Discord.

Что смотреть, если непонятно, почему стратегия ведёт себя так:

```bash
zaprctl explain general-alt3        # профили, фильтры, техники и их параметры
```

Это замена чтению `.bat`-файла: для каждого профиля печатаются порты, L3/L7,
hostlist'ы и ipset'ы (с числом реально загруженных записей), `cutoff`, а для
каждой техники — её настоящие параметры: `repeats`, `ttl`, `fooling`, позиции
split'а с маркерами (`midsld+1`, `sniext`), байты `seqovl` и файл-паттерн.

Если активный транспорт чего-то не может, `use` **откажется** переключаться:

```bash
$ sudo zaprctl use general
zaprctl: NOT switching to general — the proxy transport cannot honour it.
  ! fake (needs inject, per-packet-ttl, fooling) — cannot run at all
  ~ multisplit: seqovl 681 will be dropped (needs seq); ...
```

Это сделано специально: молча включить стратегию на `fake`, когда транспорт не
умеет инъекцию, — самое вредное, что этот инструмент мог бы сделать. Счётчики бы
шли, эффекта бы не было. Если вы понимаете, что делаете:

```bash
sudo zaprctl use general --force
```

Полезно ещё:

```bash
sudo zaprctl ipset any       # снять ограничение по ipset (обходить все адреса)
sudo zaprctl ipset loaded    # только адреса из ipset-all.txt
sudo zaprctl ipset none      # ipset-профили не сработают вообще
```

## 3. YouTube работает, Discord — нет

Проверяйте по порядку.

1. **Текст/картинки Discord — это TCP 443, голос — UDP.** Разные профили
   стратегии и разные возможности транспорта. Убедитесь, что вы смотрите на нужный:

   ```bash
   zaprctl explain general | grep -A6 udp
   ```

2. **Транспорт `proxy` вообще не видит UDP.** Тогда голос не заработает никак —
   см. раздел 4.

   ```bash
   zaprctl status | head -3      # какой транспорт активен
   ```

3. **Desync срабатывает или нет:**

   ```bash
   zaprctl stats                 # matched / desyncs / degraded / errors
   ```

   `matched` растёт, а `desyncs` нет — профиль совпал, но техники не выполнились
   (смотрите `degraded` и `zaprctl caps`). Оба нуля — не совпал ни один профиль:
   скорее всего домен не в hostlist или адрес не в ipset (`zaprctl ipset any`).

4. **Другие стратегии.** У flowseal половина ALT-вариантов существует именно
   ради Discord:

   ```bash
   for s in general-alt general-alt2 general-alt3 general-alt4; do
     sudo zaprctl use "$s" --force && zaprctl test discord.com
   done
   ```

5. **Логи:**

   ```bash
   zaprctl logs -n 100
   zaprctl logs -f               # в реальном времени, пока открываете Discord
   ```

6. **Трафик от процессов, запущенных под root, не перехватывается** (правило
   `user { > root }` разрывает петлю инъекции). Обычный Discord работает от вашего
   пользователя, но `sudo curl` для проверки — нет.

## 4. Голос в Discord (UDP 19294–19344, 50000–50100)

Работает **только** на транспорте `divert`: фейковые датаграммы инжектируются с
настоящего порта клиента перед 74-байтным пакетом IP Discovery. На `proxy` —
никак.

Паллиатив, который помогает и без UDP: прописать адреса голосовых серверов в
`/etc/hosts` (аналог кнопки «Update Hosts File» у flowseal):

```bash
sudo zaprctl hosts apply
zaprctl status | grep hosts
sudo zaprctl hosts remove     # откатить
```

Блок в `/etc/hosts` обрамлён маркерами `# >>> zapret-mac >>>` … `# <<< zapret-mac <<<`,
резервная копия — в каталоге данных, DNS-кэш сбрасывается автоматически.

Работает ли инъекция против ТСПУ — проверяется только экспериментом; см.
[limits.md](limits.md).

## 5. QUIC

Браузер сам решает, идти по QUIC (UDP/443) или по TCP. Варианта два.

* **Kill-switch (надёжно).** Демон дропает UDP/443 к целевому набору адресов, и
  браузер откатывается на TCP h2. Включается флагом демона `--block-quic`:

  ```bash
  sudo /usr/local/libexec/zapretd install-daemon \
    --data "/Library/Application Support/zapret-mac" --block-quic
  zaprctl status | grep quic     # quic  blocked (...)
  ```

* **Реальный обход QUIC** (фейковый Initial + `udplen`) есть в стратегиях
  flowseal и выполняется на `divert`. Эффективность не проверена. Резать
  CRYPTO-фреймы мы не умеем — для этого надо быть самим QUIC-клиентом.

Проверить, что профиль QUIC вообще существует в стратегии:

```bash
zaprctl explain general-exp | grep -B4 quic
```

## 6. Happ и маршрутизация

Поддерживается только Happ. Его split-routing-профиль отправляет российские
сети и все домены из zapret hostlists через физический интерфейс, а остальные
направления оставляет в VPN. PF-интерцепт ограничен физическим uplink, поэтому
трафик, уже ушедший в `utun`, не перехватывается.

После установки:

```bash
zaprctl router happ --install
# принять профиль в Happ, отключить и снова подключить Happ
sudo zaprctl restart
zaprctl test --suite discord
```

`test` и `autopick` запускай без `sudo`: PF исключает root-трафик, поэтому
проверки из-под root идут мимо zapret и дают неверный результат. Если
`scutil --nc list` показывает Happ как `Disconnected`, но его Network Extension всё ещё
держит маршрут через `utun`, сначала проверь фактический маршрут и состояние
приложения: статус `scutil` сам по себе не подтверждает отключение туннеля.
Успешный `test` при включённом Happ подтверждает доступность сервиса, но сам
по себе не доказывает, что соединение шло напрямую через zapret.

Не используй `zaprctl vpn stop` для этой схемы: команда выгружает VPN-клиент.
Если Happ не подключён, `router happ --install` выдаст предупреждение.

Для любого другого полнотуннельного VPN маршрутизатор не предназначен.
Это видно и в probe, и в предупреждениях:

```
! the default route goes through utun4: a full-tunnel VPN carries traffic
  past the point where we could desync it
```

Решение простое: либо VPN, либо это. Выключите VPN и перезапустите датапас:

```bash
sudo zaprctl restart
zaprctl status
```

## 7. Как читать предупреждения `zaprctl status`

Строки после `warnings:` — не косметика, каждая означает конкретное состояние.

| предупреждение | что делать |
|---|---|
| `the datapath is stopped (zaprctl start to resume)` | `sudo zaprctl start` |
| `the datapath is not running: ...` | причина в тексте; дальше `zaprctl logs`, `sudo zaprctl doctor` |
| `the <transport> datapath cannot honour N op(s) of this strategy: ...` | техники не выполнятся; `zaprctl explain <strategy>` покажет, что именно, и выберите другую стратегию |
| `running the degraded proxy datapath: fake/rst/seqovl ops ... cannot be honoured` | packet-датапас не поднялся; `sudo zaprctl doctor` скажет почему |
| `the capability probe could not confirm either datapath: ...` | ни один транспорт не подтверждён; смотрите вывод `sudo ./bin/zaprctl probe` |
| `the default route goes through utunN: ...` | активен VPN, раздел 6 |
| `pf drift: ...` | правила pf изменил кто-то ещё (другой инструмент сделал `pfctl -f /etc/pf.conf`); демон восстановит свой anchor, но проверьте `sudo zaprctl doctor` |
| `cannot read the ipset list: ...` | файл `lists/ipset-all.txt` недоступен; `sudo zaprctl ipset` покажет состояние |

Отдельно блок `this transport cannot honour N op(s) of the active strategy` —
это те же техники, но списком, до предупреждений.

Полная диагностика (и починка того, что можно починить):

```bash
zaprctl doctor
sudo zaprctl doctor --repair
```

Всё, что печатают команды, доступно в JSON — форма стабильная:

```bash
zaprctl status --json | jq .warnings
zaprctl list --json --transport proxy | jq '.strategies[] | {name, unsupported}'
zaprctl explain general --json | jq '.profiles[0].ops'
zaprctl logs -n 50 --json | jq -r .line      # по одному JSON-объекту на строку
```

## 8. Откат: убрать всё

Быстро, без удаления файлов:

```bash
sudo zaprctl stop          # датапас вниз, правила pf убраны
```

Полностью (порядок важен: `make uninstall` удаляет и сам `zaprctl`):

```bash
sudo zaprctl hosts remove  # если применяли пины в /etc/hosts
sudo zaprctl doctor        # посмотреть, что ещё числится нашим
make uninstall             # boot out демона, откат /etc/pf.conf, снятие pf-ссылки
sudo rm -rf "/Library/Application Support/zapret-mac"
sudo rm -f /var/log/zapret-mac.log /var/log/zapret-mac.err.log
```

Проверить, что ничего не осталось:

```bash
grep -n zapret /etc/pf.conf /etc/hosts        # ничего
launchctl print system/io.zapretmac.zapretd   # "Could not find service"
sudo pfctl -s Anchors                         # zapret-mac не упоминается
ls -l /var/run/zapret-mac.sock                # нет такого файла
```

Пошаговый вариант вручную (и что именно правится в `/etc/pf.conf`) —
в [../packaging/README.md](../packaging/README.md).
