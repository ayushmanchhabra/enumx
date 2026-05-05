# enumx

Subdomain and service enumeration.

## Getting Started

Note: Works on Linux based systems only.

```shell
git clone https://github.com/ayushmanchhabra/enumx
cd enumx
chmod +x ./enumx.sh
```

## Usage

enumx - subdomain and service enumeration

```shell
# Internet recon
./enumx.sh example.com out.csv --mode=domain --ports=true

# Internal network
./enumx.sh 192.168.1.0/24 out.csv --mode=cidr --ports=true

# From file
./enumx.sh targets.txt out.csv --mode=file --ports=false
```

stealth - TCP half open scan

```shell
# Compile binary
└─$ make
clang -Wall -Wextra -Werror -c stealth.c -o stealth.o
clang stealth.o -o stealth.exe

# Understand CLI usage
└─$ ./stealth.exe
Usage: ./stealth.exe <dst_ip> <dst_port> <src_ip>

  Performs a TCP half-open (stealth) scan:
    SYN     ->  target
    SYN-ACK <-  target  (port open)
    RST     ->  target  (tear down without completing handshake)

  src_ip  Your real IP address (needed to receive the SYN-ACK).
  Requires root / CAP_NET_RAW.

# Run a TCP half open scan.
└─$ sudo ./stealth.exe 8.8.8.8 443 172.29.14.91
[sudo] password for localghost: 
[>] SYN      172.29.14.91:37396 -> 8.8.8.8:443    seq=202411727   bytes=40
[*] Waiting for SYN-ACK (timeout 5s)...
[<] SYN-ACK  8.8.8.8:443   -> *:37396    seq=1069742210  ack=202411728
[>] RST      172.29.14.91:37396 -> 8.8.8.8:443    seq=202411728   bytes=40
[+] Port 443 is OPEN  (half-open scan complete — connection reset)
```

## Disclaimer

DISCLAIMER

This software is provided for educational and authorized security testing purposes only.

The user is solely responsible for ensuring that they have proper authorization before using this tool against any systems, networks, or assets. Unauthorized use may be illegal and may result in civil or criminal penalties.

The authors and contributors assume no liability and are not responsible for any misuse, damage, data loss, service disruption, or legal consequences resulting from the use of this software.

This tool is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.

Use at your own risk.

## License

MIT
