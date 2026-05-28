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

# Get IP address
└─$ dig +short google.com
8.8.8.8

# Understand CLI usage
└─$ ./killchain.exe 
Usage:
  ./killchain.exe <dst_ip> [output.csv] [--src <ip>] [--port <N>] [--timeout <secs>]

  --src <ip>       override auto-detected source IP
  --port <N>       scan a single port instead of 1-65535
  --timeout <secs> drain window after last SYN (default 5)

  CSV columns : host, port, output
  output field: open  seq=<N>  ack_seq=<N>  win=<N>
  Requires root / CAP_NET_RAW.

# Run a TCP half open scan.
└─$ sudo ./killchain.exe 8.8.8.8 ./out.csv
[*] Auto-detected source IP: 172.29.14.91
[*] Scanning 8.8.8.8 ports 1-65535 (src 172.29.14.91 sport 60000 timeout 5s)...
[+] OPEN  8.8.8.8:53
[+] OPEN  8.8.8.8:853
[+] OPEN  8.8.8.8:443
[*] SYNs sent. Waiting 5s for responses...

PORT      STATE
53        open
443       open
853       open

nmap -p 53,443,853 -sCV 8.8.8.8

[*] Done. 3 open port(s).

└─$ cat out.csv 
host,port,output
"8.8.8.8",53,"open  seq=3337366976  ack_seq=1606235609  win=65535"
"8.8.8.8",443,"open  seq=3539581131  ack_seq=1800429215  win=65535"
"8.8.8.8",853,"open  seq=471598755  ack_seq=466585909  win=65535"
```

## Disclaimer

**For authorized use only**. This tool is provided for educational and legitimate security testing purposes. You are solely responsible for obtaining proper authorization before use. Unauthorized use may be illegal.

Provided "as is," with no warranties. The authors are not liable for any misuse or damages.

_Use at your own risk._

## License

MIT
