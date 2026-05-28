# killchain

Super fast TCP scanner.

## Getting Started

> Note: Linux environment is required. This does not work on Windows since raw sockets have been heavily restricted since Windows XP SP2 (2004). MacOS support is possible (PR is welcome).

```shell
git clone https://github.com/ayushmanchhabra/killchain
cd killchain
sudo apt install clang clang-format clang-tidy
```

## Usage

```shell
# Compile binary
└─$ make
clang -Wall -Wextra -Werror -c killchain.c -o killchain.o
clang killchain.o -o killchain.exe
sha256sum ./killchain.c > ./shasum.txt
sha256sum ./killchain.exe >> ./shasum.txt
sha256sum ./Makefile >> ./shasum.txt

# Learn the API
└─$ ./killchain.exe 
Usage:
  ./killchain.exe <dst_ip|cidr> [output.csv] [--src <ip>] [--port <N>]
     [--timeout <secs>] [--ping-timeout <secs>]

  --src <ip>           override auto-detected source IP
  --port <N>           scan a single port instead of 1-65535
  --timeout <secs>     SYN drain window (default 5)
  --ping-timeout <sec> ICMP sweep wait (default 2)

  Examples:
    ./killchain.exe 10.0.0.1
    ./killchain.exe 10.0.0.0/24
    ./killchain.exe 192.168.1.0/24 out.csv --port 80 --timeout 3

  Subnet limits: /16 to /32  (up to 65534 hosts)
  CSV columns  : host, port, output
  output field : open  seq=<N>  ack_seq=<N>  win=<N>
  Requires root / CAP_NET_RAW.
```

## Disclaimer

**For authorized use only**. This tool is provided for educational and legitimate security testing purposes. You are solely responsible for obtaining proper authorization before use. Unauthorized use may be illegal.

Provided "as is," with no warranties. The authors are not liable for any misuse or damages.

_Use at your own risk._

## License

MIT
