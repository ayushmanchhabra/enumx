# killchain

Multithreaded network scanner that crafts raw IP/TCP packets by hand — no libpcap, no wrappers.

Supports SYN port scanning and ICMP host discovery across single hosts and subnets, hardened with clang-tidy, Valgrind, and AddressSanitizer.

## Getting Started

> Note: Linux environment is required. This does not work on Windows since raw sockets have been heavily restricted since Windows XP SP2 (2004). MacOS and Android support is possible (PR is welcome).

```shell
git clone https://github.com/ayushmanchhabra/killchain
cd killchain
sudo apt install clang clang-format clang-tidy valgrind
```

## Usage

```shell
# Compile binary
└─$ make

# API
└─$ sudo ./out/bin/killchain
Usage: killchain <IP|CIDR> <-|out.csv|out.json|out.xml>

┌──(localghost㉿Ayush)-[~/ayushmanchhabra/killchain]
└─$ sudo ./out/bin/killchain 8.8.8.8 -
[!] By using this tool you confirm you have explicit permission to test the target.
Unauthorized use is illegal and is your sole responsibility. Proceed? (y/n): y
Starting scan on: 8.8.8.8
Scan started: 2026-06-22 20:03:18

Do you want to check if host(s) are up? (y/n): y

IP address detected: 8.8.8.8

HOST             STATUS   LATENCY
8.8.8.8          UP        10 ms

Do you want to check which port(s) are open? (y/n): y

HOST             PORT     STATE
8.8.8.8          53       OPEN
8.8.8.8          443      OPEN
8.8.8.8          853      OPEN

3 open port(s) found.

Scan complete: 2026-06-22 20:03:22

```

## Disclaimer

**For authorized use only**. This tool is provided for educational and legitimate security testing purposes. You are solely responsible for obtaining proper authorization before use. Unauthorized use may be illegal.

Provided "as is," with no warranties. The authors are not liable for any misuse or damages.

_Use at your own risk._

## License

MIT
