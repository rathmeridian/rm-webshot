# rm-webshot
A simple open-source utility from Rath Meridian. Adversary Insight, Executive
Clarity.

https://rathmeridian.com/

A small command line utility that scans hosts for HTTP and HTTPS services and,
optionally, captures a screenshot of every web service it finds.

Written in plain C11 against libc and pthreads only, so it builds on
essentially any Linux distribution without pulling in third party libraries.

## Legal and ethical use

Port scanning hosts you do not own or have written permission to test is
illegal in many jurisdictions and breaches the terms of service of most
hosting providers. Point this at your own infrastructure, a lab network, or
systems you have been explicitly authorised to assess. You are responsible for
how you use it.

## Requirements

Build time:

- a C compiler (gcc or clang)
- `make`
- libc and pthreads

That is all. There is no build time dependency on a browser or on any
networking library.

Run time:

- Nothing extra for scanning.
- For screenshots (`-s`), a Chromium-family browser must be on `PATH`. The
  first of these that is found is used:
  `chromium`, `chromium-browser`, `google-chrome`, `google-chrome-stable`,
  `brave-browser`.

Installing a browser:

```sh
# Debian / Ubuntu
sudo apt install chromium

# Fedora
sudo dnf install chromium

# Arch
sudo pacman -S chromium
```

Firefox is not supported. Its headless screenshot mode takes different flags
and does not accept an arbitrary output path the same way.

## Build

```sh
make                  # builds ./rm-webshot
sudo make install     # optional, installs to /usr/local/bin
```

Other targets:

```sh
make debug     # -O0 -g with AddressSanitizer and UBSan, for hacking on the code
make clean
make uninstall
```

To install somewhere else:

```sh
make install PREFIX=$HOME/.local
```

## Usage

```
rm-webshot [options] <target> [target ...]
```

Targets can be mixed freely on one command line:

- a literal IPv4 or IPv6 address
- an IPv4 CIDR block, for example 192.0.2.0/24
- a hostname, for example `example.com`

A hostname that resolves to several addresses is scanned at every address, and
all of its screenshots land in the same directory.

### Options

- `-p, --ports <list>` — ports to scan; comma separated, ranges allowed
  (`-p 80,443,8000-8100`). Default: `80,443,8000,8008,8080,8443,8888`
- `-t, --threads <n>` — concurrent scan workers (default 64, max 1024)
- `-T, --timeout <ms>` — per connection timeout in milliseconds (default 2000)
- `-s, --screenshot` — capture screenshots; off by default
- `-o, --output <dir>` — root output directory (default `scan-output`)
- `--shot-timeout <s>` — seconds allowed per screenshot (default 20)
- `--window <WxH>` — browser viewport size (default 1280x1024)
- `--force-large-range` — permit CIDR blocks wider than /24
- `-v, --verbose` — also report closed ports, and let browser output through
- `-h, --help` — show help

### Examples

Scan one host with the default port set, no screenshots:

```sh
./rm-webshot example.com
```

Scan a subnet and capture what you find:

```sh
./rm-webshot -s 192.0.2.0/24
```

Scan several targets on specific ports, with a shorter timeout and more
workers, writing results elsewhere:

```sh
./rm-webshot -s -p 80,443,8080-8090 -T 800 -t 128 -o /tmp/results \
    example.com 192.0.2.10 192.0.2.0/24
```

## Output layout

Screenshots are written as:

```
<output>/<host>/<ip>_<port>_screenshot<N>.png
```

`<host>` is the target exactly as you typed it, so results map back to your
input. `<N>` counts up per host, so a host with three web services gets
`screenshot1`, `screenshot2` and `screenshot3`.

Example:

```
scan-output/
├── example.com/
│   ├── 93.184.216.34_80_screenshot1.png
│   └── 93.184.216.34_443_screenshot2.png
└── 10.0.0.7/
    └── 10.0.0.7_8080_screenshot1.png
```

Directory and file names are sanitised: anything that is not a letter, digit,
dot, dash or underscore becomes an underscore. This is a safety measure, not
cosmetics, since a hostile DNS name containing `/` or `..` could otherwise
steer writes outside the output directory. A side effect is that IPv6
addresses appear with underscores in place of colons, so `::1` becomes `__1`.

## How it works

1. **Target expansion** (`src/targets.c`) — each argument is classified as a
   literal address, a CIDR block or a hostname. Names are resolved with
   `getaddrinfo`; CIDR blocks are expanded, skipping the network and broadcast
   addresses for /30 and wider.
2. **Scanning** (`src/scanner.c`) — every host/port pair becomes a job on a
   thread pool. Each job does a non-blocking `connect()` with `poll()` and a
   hard timeout, so unreachable hosts cost the timeout rather than the kernel's
   default retry period.
3. **Service detection** (`src/scanner.c`) — an open port gets a one-shot
   `HEAD / HTTP/1.0` probe. A reply beginning `HTTP/` means plaintext HTTP; a
   TLS alert or handshake record (first byte `0x15` or `0x16`) means HTTPS. If
   the probe is inconclusive the port number decides, and ports with no web
   convention are reported as open but skipped for screenshots.
4. **Capture** (`src/screenshot.c`) — each web service is opened in headless
   Chromium via `fork()` and `execvp()`. No shell is involved, so a hostile
   hostname cannot be interpreted as a command. Each capture gets a throwaway
   profile directory, and the browser is killed if it exceeds `--shot-timeout`.

### Concurrency model

Scanning is parallel because it is almost entirely I/O wait. Screenshots are
sequential because each one starts a full browser process, and running many at
once will exhaust memory on a modest machine.

## Editing the code

The source is organised so that each concern lives in one place:

- `src/main.c` — option parsing, orchestration, output paths, reporting
- `src/targets.c` / `.h` — argument classification, DNS, CIDR expansion
- `src/scanner.c` / `.h` — TCP connect and HTTP/HTTPS probing
- `src/screenshot.c` / `.h` — browser detection, URL building, capture
- `src/threadpool.c` / `.h` — generic worker pool

Some things you may want to change:

- **Default ports** — `DEFAULT_PORTS` at the top of `src/main.c`.
- **CIDR safety limit** — `CIDR_SAFE_PREFIX` in `src/targets.c`.
- **Which browsers are tried** — `screenshot_browser_candidates` in
  `src/screenshot.c`.
- **Browser flags** — the `argv` array in `run_browser()` in
  `src/screenshot.c`. Note `--ignore-certificate-errors` is set deliberately,
  since self-signed certificates are common on the kind of hosts this tool
  tends to find.
- **Parallel screenshots** — `run_screenshot_pass()` in `src/main.c` is a
  simple loop. You could feed it to a second, small thread pool (2 to 4
  workers), but the per-host counter would then need a mutex.
- **Port-to-scheme hints** — `scanner_guess_by_port()` in `src/scanner.c`,
  used when the probe cannot tell what a service is.

When changing anything, build with `make debug` first: it enables
AddressSanitizer and UndefinedBehaviorSanitizer, which catch the memory and
threading mistakes that are easy to introduce here.

## Exit codes

- `0` — ran to completion (this does not imply anything was found)
- `1` — bad arguments, no usable targets, or `-s` given with no browser present
