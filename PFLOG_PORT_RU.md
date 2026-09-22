# Штатный macOS transport: PF log + BPF

В `zapret-for-mac` пакетный режим `divert` теперь использует рабочую на macOS
схему:

```text
приложение
    ↓
PF: block out log (all, to pflogN) quick on en0
    ├── оригинал заблокирован
    └── копия → pflogN → strategy engine → BPF → физический интерфейс
```

VPN, удалённый сервер, NetworkExtension, kext и отключение SIP не нужны. Ответы
сервера идут прямо в socket приложения; userspace TCP/IP stack не используется.

## Установка и запуск

```bash
make install
zaprctl router happ --install
# принять профиль в Happ и переподключить Happ
sudo zaprctl start
zaprctl status
zaprctl test --suite discord
```

`make install` устанавливает один daemon и один CLI, фиксирует transport
`divert`, активирует `cloud-gaming` и копирует все стратегии, fake-пейлоады и
листы в `/Library/Application Support/zapret-mac`. Отдельный dev-каталог и
`run-pflog-dev.sh` больше не используются.

Для Happ включается отдельный policy profile:

```bash
zaprctl router happ --install
```

Он отправляет российские geosite/geoip, домены из hostlists zapret, исключённые
от desync домены (`list-exclude.txt`) и отдельный VK/VK Play список напрямую
через физический интерфейс. Остальной трафик остаётся в VPN.
После импорта профиля Happ нужно принять профиль и переподключить VPN.

Правила PF ограничены физическим uplink (`on en0`), поэтому трафик, уже
маршрутизированный Happ в `utun`, не попадает в zapret. Root-owned пакеты VPN
также исключены правилом `user { > root }`, чтобы не блокировать сам туннель.

Роутер намеренно поддерживает только Happ: у других VPN-клиентов нет общего
API для импорта split-routing-профиля. `router happ` проверяет, что Happ
действительно обнаружен, и отказывается менять маршрутизацию другого VPN.

## Discord и cloud gaming

`cloud-gaming.toml` основан на лучшей в живом Discord-тесте стратегии ALT3 и
добавляет:

- Discord API, Gateway, CDN, media, updater и UDP voice/STUN;
- YouTube/Google hostlists из исходного проекта;
- игровой TCP/UDP диапазон `1024-65535`, ограниченный штатным `ipset-all.txt`.

Адреса игровых узлов могут меняться, поэтому они не зашиваются в код как
случайные IP конкретной сессии. Пользовательские домены и CIDR по-прежнему
добавляются через `list-general-user.txt` и `ipset-all.txt` установленного
каталога данных.

Для стабильного сравнения стратегий:

```bash
zaprctl autopick --suite discord --no-early-stop --rounds 3
```

Кандидат с `2/3` и медианой 40 ms не быстрее рабочего `3/3`: медиана первого
считает только успешные запросы и не учитывает timeout провалившейся проверки.

## Аварийное восстановление

```bash
sudo /usr/local/libexec/zapretd guard --verbose
```

Команда сама определяет, используется ли `com.apple/zapret-mac` или fallback
anchor из `/etc/pf.conf`, и очищает только правила zapret-mac. Установленный
launchd guard выполняет ту же проверку автоматически.

Если после запуска пропал весь интернет, сначала останови datapath:

```bash
sudo zaprctl stop
```

Проверь, что в правилах нет старого standalone-anchor:

```bash
sudo pfctl -a zapret-probe -sr
sudo pfctl -a zapret-probe -F all
```

После обновления проверь активный anchor:

```bash
sudo pfctl -a com.apple/zapret-mac -sr
```

В правилах должны быть одновременно `quick on en0` и `user { > root }`.
Отсутствие `on en0` означает старую сборку, которая могла перехватывать VPN,
а отсутствие `user { > root }` — сборку с ошибочным `--no-exempt-root`.

## Проверка transport разработчиком

Live-тест требует root и реального PF/BPF:

```bash
sudo env ZAPRET_LIVE_PFLOG=1 CGO_ENABLED=0 \
  go test ./internal/transport/divert -run TestLivePFLogIntercept -v
```

На целевом Apple Silicon Mac тест прошёл: PF доставил заблокированный SYN на
`pflog9`, пакет был разобран и повторно выпущен через `en0`.
