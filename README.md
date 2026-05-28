# killchain

Super fast TCP scanner.

## Getting Started

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

# Get IP address
└─$ dig +short google.com
8.8.8.8

# Get src_ip
└─$ ip addr show eth0

# Understand CLI usage
└─$ ./killchain.exe 
Usage:
  ./killchain.exe <dst_ip> <src_ip> [output.csv]              # scan ports 1-65535
  ./killchain.exe <dst_ip> <src_ip> [output.csv] --port <N>   # scan one port

  CSV columns: host, port, output
  Requires root / CAP_NET_RAW.

# Run a TCP half open scan.
└─$ sudo ./killchain.exe 8.8.8.8 172.29.14.91 ./out.csv
[*] Scanning 8.8.8.8 ports 1-65535 (src 172.29.14.91 sport 60000)...
[<] SYN-ACK  8.8.8.8:53     OPEN
[<] SYN-ACK  8.8.8.8:443    OPEN
[<] SYN-ACK  8.8.8.8:853    OPEN
[*] SYNs sent. Waiting 3s for responses...

PORT      STATE
53        open
443       open
853       open

[*] Done. 3 open port(s).

└─$ cat out.csv 
host,port,output
"8.8.8.8",53,"open"
"8.8.8.8",443,"open"
"8.8.8.8",853,"open"
```

## Disclaimer

**For authorized use only**. This tool is provided for educational and legitimate security testing purposes. You are solely responsible for obtaining proper authorization before use. Unauthorized use may be illegal.

Provided "as is," with no warranties. The authors are not liable for any misuse or damages.

_Use at your own risk._

## License

MIT
