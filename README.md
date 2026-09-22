# zapret-for-mac

Current development line: **0.2.0**. See [CHANGELOG.md](CHANGELOG.md) for the
porting and routing changes.

> **Native pflog/BPF transport.** The daemon captures PF-logged originals through
> a private `pflog` interface, applies the desync strategy, and re-emits packets
> through BPF. `cloud-gaming` is the installed default for Discord, YouTube and
> cloud gaming; no second checkout or development launcher is required.

**A complete macOS port of [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) — DPI bypass for Discord and YouTube, rewritten from scratch in Go for Apple Silicon.**

> **Полный порт [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) на macOS** — обход DPI для Discord и YouTube, переписанный с нуля на Go под Apple Silicon.

[![macOS](https://img.shields.io/badge/macOS-13%2B-black?logo=apple)](#requirements)
[![Apple Silicon](https://img.shields.io/badge/Apple%20Silicon-arm64-black?logo=apple)](#requirements)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

All 21 upstream strategies are here, converted automatically from the original `.bat` files with their exact parameters preserved — `seqovl` offsets, split positions, fooling modes, repeat counts and the binary fake payloads from `bin/*.bin`. No hand-tuning, no guesswork: the converter reads upstream and fails loudly on any flag it does not understand.

> Здесь все 21 стратегия из upstream, сконвертированные автоматически из оригинальных `.bat` с сохранением точных параметров — смещений `seqovl`, позиций split, режимов fooling, числа повторов и бинарных fake-пейлоадов из `bin/*.bin`. Никакой ручной подгонки: конвертер читает upstream и падает с ошибкой на любом неизвестном флаге.

---

## Quick start / Быстрый старт

### Homebrew

```bash
brew tap naladwepo/zapret
brew install --cask zapret-for-mac

sudo /usr/local/libexec/zapretd install-daemon \
  --plist /Library/LaunchDaemons/io.zapretmac.zapretd.plist \
  --data /opt/homebrew/var/zapret-mac \
  --transport divert

sudo zaprctl vpn stop            # a full-tunnel VPN makes desync pointless
sudo zaprctl use cloud-gaming
zaprctl test --suite discord
```

> **Через Homebrew.** `brew tap naladwepo/zapret` и `brew install --cask zapret-for-mac` ставят готовые arm64-бинарники и данные. `install-daemon --transport divert` регистрирует штатный pflog/BPF daemon в launchd; `sudo zaprctl use cloud-gaming` включает общий профиль Discord, YouTube и cloud gaming.

### From source / Из исходников

```bash
git clone https://github.com/naladwepo/zapret-for-mac.git
cd zapret-for-mac
make build

# Install the daemon, pflog/BPF transport, lists and cloud-gaming strategy
make install

# Import the Happ split-routing profile, accept it, and reconnect Happ
zaprctl router happ --install
sudo zaprctl start
zaprctl test --suite discord
```

> **Быстрый старт.** `make install` собирает и ставит один штатный демон, списки и стратегию `cloud-gaming`; отдельный dev-каталог больше не нужен. Убедись, что Happ подключён, затем запусти `zaprctl router happ --install` и переподключи VPN. После этого `zaprctl test --suite discord` проверит API, Gateway WebSocket, CDN, updater и голосовой UDP/STUN без ручного запуска Discord.

**Requirements:** macOS on Apple Silicon, Go 1.26+, root to run. **Not** required: disabling SIP, kernel extensions, NetworkExtension entitlements, a paid Apple Developer account, a reboot, or notarization.

> **Требования:** macOS на Apple Silicon, Go 1.26+, root для запуска. **Не** требуется: отключать SIP, kext, NetworkExtension, платный Apple Developer, перезагрузка, нотаризация.

Подробная схема маршрутизации для Happ: [PFLOG_PORT_RU.md](PFLOG_PORT_RU.md).

### Автозапуск и смена профилей

После `make install` сам `zapretd` запускается автоматически через системный
`launchd`. Профиль Happ сохраняется внутри Happ, поэтому после перезагрузки
достаточно включить у Happ его штатное подключение последнего профиля; повторно
импортировать маршрут не требуется. `zaprctl router happ --install` проверяет,
что активен именно Happ, и отказывается работать поверх другого VPN.

Для автоматического запуска Happ и обновления маршрута при изменении списков:

```bash
zaprctl autostart install
zaprctl autostart status
```

Пользовательский LaunchAgent запускает Happ, пытается подключить последний
сервис через `scutil` и следит за `list-general.txt`, `list-google.txt`,
`list-general-user.txt`, `list-exclude.txt`, `list-exclude-user.txt` и
`list-vk.txt`. При изменении любого из них профиль Happ переимпортируется.

Запуск VPN из root-daemon намеренно не выполняется: Happ — пользовательская
Network Extension, и macOS не даёт безопасного универсального способа управлять
ею из system LaunchDaemon. Если поменял профиль в Happ, просто переподключи VPN.
Если поменял стратегию zapret, выполни `sudo zaprctl use <strategy>` — роутер при
этом менять не нужно.

---

## Why this is not a straight port / Почему это не портирование «в лоб»

`winws` (Windows) and `nfqws` (Linux) work the same way: the kernel hands a packet to userspace, the program edits or drops it and injects its own — WinDivert on Windows, NFQUEUE on Linux, divert sockets on FreeBSD. **macOS has none of that.** `ipfw` and `ipdivert` were removed in OS X 10.10, and Apple's `pf` has no `divert-to` and no `divert-packet` — verified on a live machine: `man 5 pf.conf` lists only `route-to`, `reply-to`, `dup-to`, `rdr`, `nat` and `dummynet`, and the kernel exports no `div_*` symbol at all. bol-van says it himself in `docs/bsd.en.md` ("*dvtws does compile but is useless*"), and `zapret2` declares macOS unsupported outright.

> `winws` (Windows) и `nfqws` (Linux) устроены одинаково: ядро отдаёт пакет в userspace, программа его правит или дропает и инжектит свои — WinDivert на Windows, NFQUEUE на Linux, divert-сокеты на FreeBSD. **На macOS ничего этого нет.** `ipfw` вместе с `ipdivert` вырезаны ещё в OS X 10.10, а в pf от Apple нет ни `divert-to`, ни `divert-packet` — проверено на живой машине: в `man 5 pf.conf` есть только `route-to`, `reply-to`, `dup-to`, `rdr`, `nat` и `dummynet`, а ядро не экспортирует ни одного символа `div_*`. Сам bol-van пишет об этом в `docs/bsd.en.md` («*dvtws does compile but is useless*»), а в `zapret2` macOS объявлен неподдерживаемым.

So the interception core had to be rebuilt on primitives macOS does have.

> Поэтому ядро перехвата пришлось собрать заново — на тех примитивах, которые в macOS есть.

---

## How it works / Как это устроено

```
                    ┌──────────────────────────────────────────────┐
   application  ──► │ pf: block out log ... quick on en0           │ ──► /dev/bpfN
                    └──────────────────────────────────────────────┘      (DLT_PFLOG;
                                                                           original dropped)
                                          │
                            desync engine │ split / fake / seqovl / ttl / ip-id
                                          ▼
                    ┌──────────────────────────────────────────────┐
                    │ BPF Ethernet write on en0 (bypasses pf)      │ ──► the wire
                    └──────────────────────────────────────────────┘

   server replies ──► en0 ──► straight into the application's own socket
                              (inbound is never steered: no userspace TCP stack)
```

**`divert` — the packet datapath.** A pf rule logs matching outbound packets to a dedicated `pflog` interface and blocks the originals. The daemon reads DLT_PFLOG records, applies the strategy, then emits raw Ethernet frames through `/dev/bpfN`, below pf. There is no reinjection loop, while TCP sequence numbers, per-packet TTL, `ip.id`, deliberately bad checksums and TCP options remain under our control. Inbound traffic stays on the kernel socket path and the application's real 4-tuple is preserved.

> **`divert` — пакетный датапас.** PF логирует подходящие исходящие пакеты в отдельный `pflog` и блокирует оригиналы. Демон читает DLT_PFLOG, применяет стратегию и выпускает сырые Ethernet-кадры через `/dev/bpfN` ниже PF. Петли повторного перехвата нет; доступны TCP sequence, TTL на каждый пакет, `ip.id`, намеренно битые checksums и TCP options. Ответы сервера остаются на штатном пути ядра, настоящий 4-tuple приложения сохраняется.

**`proxy` — the fallback.** `pf rdr` to a local listener plus `ioctl(DIOCNATLOOK)` to recover the original destination — the way zapret's `tpws` works on macOS. TCP only, byte-level tricks only: `send()` boundaries, `tlsrec`, `tamper`, disorder via TTL 1. No `fake`, no `seqovl`, no UDP.

> **`proxy` — резервный режим.** `pf rdr` на локальный порт плюс `ioctl(DIOCNATLOOK)` для восстановления настоящего адресата — так работает `tpws` из zapret на macOS. Только TCP и только байтовые трюки: границы `send()`, `tlsrec`, `tamper`, disorder через TTL 1. Ни `fake`, ни `seqovl`, ни UDP.

**No edit to `/etc/pf.conf`.** A stock file already declares `anchor "com.apple/*"`, and a trailing `/*` makes pf evaluate every nested sub-anchor — which is created simply by loading rules into it. So rules go into `com.apple/zapret-mac` and become live with no system file touched, exactly the way Apple's own services inject theirs at runtime.

> **`/etc/pf.conf` не правится.** Стоковый файл уже объявляет `anchor "com.apple/*"`, а суффикс `/*` заставляет pf вычислять все вложенные под-анкоры — а под-анкор создаётся самим фактом загрузки в него правил. Поэтому правила уходят в `com.apple/zapret-mac` и становятся активными без единой правки системного файла — ровно так же свои правила в рантайме добавляют сервисы самой Apple.

---

## Verified on real hardware / Проверено на живом железе

The live `TestLivePFLogIntercept` integration test was run on the target Apple Silicon Mac with SIP enabled. It observed the blocked SYN on `pflog9`, parsed the aligned DLT_PFLOG header and re-injected the IPv4 packet through the physical interface:

> Live-тест `TestLivePFLogIntercept` пройден на целевом Apple Silicon Mac с включённым SIP: заблокированный SYN пришёл на `pflog9`, DLT_PFLOG был разобран, а IPv4-пакет повторно выпущен через физический интерфейс.

| Property | Evidence |
|---|---|
| PF log/drop interception | blocked outbound SYN captured on `pflog9` |
| DLT_PFLOG parsing | IP payload found at the required word-aligned offset |
| BPF re-injection | captured IPv4 packet emitted through `en0` |
| `/etc/pf.conf` untouched | rules loaded below the stock `com.apple/*` wildcard |

---

## What works, and what cannot / Что работает, а что нет

| winws feature | `divert` | `proxy` |
|---|---|---|
| `multisplit` / `multidisorder`, all split-position markers | full | approximate |
| `--dpi-desync-split-seqovl` (**15 of 21 upstream strategies**) | full | **no** |
| `fake`, `fakedsplit`, `fakeddisorder`, `hostfakesplit`, `syndata`, `rst` | full | **no** |
| `--dpi-desync-fooling` (badsum, badseq, md5sig, ts, datanoack) | full | **no** |
| `--ip-id=zero`/`seq`, `ipfrag`, IPv6 ext headers | full | **no** |
| per-packet TTL / `--dpi-desync-autottl` | full | **no** |
| `udplen`, QUIC / Discord / STUN fakes | full | **no** |
| `tamper`, `tlsrec`, hostlists, ipset, `--new` chain, cutoff | full | full |
| `--oob` / `--disoob` | **no** | **no** |

The CLI never hides this: `zaprctl list` marks, per strategy, exactly which ops the active transport cannot honour, and `zaprctl use` refuses to silently activate a strategy whose core technique would be skipped. Full table with reasons: [docs/limits.md](docs/limits.md).

> CLI это не скрывает: `zaprctl list` для каждой стратегии помечает, какие именно техники активный транспорт выполнить не может, а `zaprctl use` не даёт молча включить стратегию, у которой отключится ключевая техника. Полная таблица с причинами — в [docs/limits.md](docs/limits.md).

**Discord voice (UDP 19294–19344, 50000–50100):** mechanically reproduced in `divert` only — the fake datagrams are injected with a chosen TTL **from the client's own source port** before the 74-byte IP-Discovery packet, exactly as winws does. Whether that defeats a given DPI box is an empirical question no local test can answer. In `proxy` voice does not work at all.

> **Discord voice (UDP 19294–19344, 50000–50100):** механика воспроизведена только в `divert` — фейковые датаграммы инжектируются с заданным TTL **с настоящего исходного порта клиента** перед 74-байтным пакетом IP Discovery, ровно как это делает winws. Пробьёт ли это конкретный ТСПУ — вопрос эмпирический, локальным тестом не проверяется. В `proxy` голос не работает никак.

---

## Commands / Команды

```bash
zaprctl status                  # transport, strategy, counters, pf state, warnings
zaprctl list                    # strategies + what the transport cannot honour
zaprctl explain general         # compiled profiles: filters, ops, real parameters
sudo zaprctl use cloud-gaming   # Discord + YouTube + cloud-gaming default
zaprctl autopick --suite discord --no-early-stop --rounds 3
zaprctl test --suite discord    # API, WSS, CDN, updater and UDP/STUN
zaprctl doctor [--repair]       # diagnostics; fixes what is safely ours
sudo zaprctl vpn stop|start     # the VPN that blocks the packet datapath
zaprctl router happ --install   # проверка Happ + импорт split-routing профиля
zaprctl autostart install      # запуск Happ и watcher списков при входе в систему
sudo zaprctl probe               # capability probe, встроенный в этот CLI
sudo zaprctl hosts apply        # /etc/hosts pinning for Discord voice
sudo zaprctl ipset any          # upstream's tri-state ipset switch
zaprctl logs -f
```

Run `test` and `autopick` **without `sudo`**. The default PF rules exempt root
traffic, so root-owned probes bypass zapret and can give a false failure or
select the wrong strategy. The control socket grants access to the `admin` group.

> Те же команды по-русски: `status` — транспорт, стратегия, счётчики, состояние pf и предупреждения; `list` — стратегии и что из них не потянет активный транспорт; `explain` — скомпилированные профили с реальными параметрами (замена чтению `.bat`); `use` — сменить стратегию; `autopick` — перебрать все и оставить рабочую; `test` — проверка связности через датапас; `doctor` — диагностика и починка своего мусора; `vpn stop/start` — корректно остановить и вернуть VPN; `hosts apply` — пины IP для Discord voice; `ipset` — tri-state переключатель из upstream; `logs` — журнал демона.

---

## If something breaks / Если что-то сломалось

One command always restores normal networking. It resolves the effective
`com.apple/zapret-mac` sub-anchor (or the pf.conf fallback) and empties it:

```bash
sudo /usr/local/libexec/zapretd guard --verbose
```

A `launchd` guard does this automatically every 5 seconds whenever no daemon owns the anchor, so a `kill -9` cannot leave pf dropping your traffic.

> Одна команда всегда возвращает сеть в норму и сама находит фактический PF-анкор: `sudo /usr/local/libexec/zapretd guard --verbose`. Раз в 5 секунд то же делает launchd-страж, если анкором никто не владеет.

Full uninstall: `make uninstall` — removes the binaries, both launchd jobs and the `/etc/hosts` block if it was applied.

> Полное удаление: `make uninstall` — снимает бинари, обе launchd-задачи и блок в `/etc/hosts`, если он применялся.

---

## Known limitations / Известные ограничения

* Root-owned traffic is intentionally exempt from interception via `user { > root }`. This is the loop breaker for injected packets and lets Happ's own VPN transport reach its server while user-owned Direct connections are processed.
* Internet Sharing is not supported.
* A blind full-tunnel VPN makes direct desync impossible because its sockets carry tunnel addresses. With the Happ split-routing profile (`zaprctl router happ --install`), `--allow-vpn` lets zapret process physical Direct connections while foreign traffic remains tunneled.
* Apple documents pf as "not API" ([TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)) and there is no arbitration between tools. The daemon watches its anchor for drift and reloads, but a conflict with something else running `pfctl -f /etc/pf.conf` is possible by design.
* Strategies decay: `seqovl=681` works only while the DPI reassembles naively. `cmd/batconv` re-imports upstream at any time.

> * Трафик процессов, запущенных от **root**, намеренно исключён из перехвата правилом `user { > root }`. Это разрывает петлю инжекции и позволяет собственному VPN-трафику Happ доходить до сервера, пока пользовательские Direct-соединения обрабатываются zapret.
> * Internet Sharing не поддерживается.
> * При слепом полнотуннельном VPN десинхронизация невозможна: сокеты несут адрес туннеля. В split-routing профиле (`zaprctl router happ --install` для Happ) `--allow-vpn` позволяет zapret обрабатывать физические Direct-соединения, а иностранный трафик оставляет в VPN.
> * Apple документирует pf как «не API» ([TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)), арбитража между инструментами не существует. Демон следит за дрейфом своего анкора и восстанавливает его, но конфликт с чем-то, что делает `pfctl -f /etc/pf.conf`, возможен принципиально.
> * Стратегии деградируют: `seqovl=681` работает, пока DPI собирает поток наивно. `cmd/batconv` в любой момент перечитывает upstream.

Everything that is unverified, approximated or deliberately unimplemented is written down without hedging in [docs/known-issues.md](docs/known-issues.md).

> Всё, что не проверено, аппроксимировано или сознательно не реализовано, выписано без смягчений в [docs/known-issues.md](docs/known-issues.md).

---

## Layout / Структура

```
cmd/zapretd            root daemon: launchd, supervisor, journal-based rollback
cmd/zaprctl            CLI over the unix socket /var/run/zapret-mac.sock
cmd/zaprctl/probe.go   embedded capability probe (`zaprctl probe`, needs root)
cmd/batconv            converter: upstream .bat strategies → TOML
internal/proto         IPv4/IPv6/TCP/UDP, checksums, fragmentation, TLS ClientHello,
                       split-position markers, QUIC Initial decryption → SNI,
                       STUN / Discord IP-Discovery / WireGuard / DHT
internal/desync        techniques: multisplit, multidisorder, fakedsplit, fakeddisorder,
                       hostfakesplit, fake, rst, syndata, udplen, ipfrag, hopbyhop,
                       tamper, tlsrec, wssize, ip_id, block
internal/engine        profile selection, flow state, cutoff/start, autottl, Caps gating
internal/strategy      TOML strategy loader and compiler
internal/lists         hostlists (suffix matching) and ipsets (32k CIDRs)
internal/transport     divert (pflog + BPF) and proxy (pf rdr + DIOCNATLOOK)
internal/netcfg        pf: token, wildcard sub-anchor, tables, rollback journal
internal/vpn           detect and cleanly stop VPN software holding the default route
internal/diag          capability detection, doctor, self-test, strategy autopick
strategies/*.toml      21 upstream strategies + cloud-gaming integration profile
lists/, fakes/         domain/CIDR lists and fake payloads from upstream
```

---

## Credits / Благодарности

* [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) — the strategies, lists and fake payloads this port reproduces.
* [bol-van/zapret](https://github.com/bol-van/zapret) — the desync engine whose packet-level semantics were ported.

> Стратегии, списки и fake-пейлоады происходят из [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube); семантика desync-техник портирована из [bol-van/zapret](https://github.com/bol-van/zapret).

## License / Лицензия

MIT — see [LICENSE](LICENSE). Upstream strategies, lists and payloads remain under their original MIT terms.

> MIT — см. [LICENSE](LICENSE). Стратегии, списки и пейлоады из upstream остаются под своей исходной лицензией MIT.
