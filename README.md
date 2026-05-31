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

# API Usage (like sqlmap user interface, cache input wherever possible)
└─$ ./killchain
  Usage: killchain <IP|CIDR> <-|out.{csv,json,xml}>
  -> IP -> remote (ICMP) or local (ARP) subnet
  -> Host status -> Y/n
  -> Check open ports via SYN scan -> y/N
  -> service check via banner grabbing -> y/N
  -> output -> (-)stdout/(c)sv/(j)son/(x)ml
```

## Disclaimer

**For authorized use only**. This tool is provided for educational and legitimate security testing purposes. You are solely responsible for obtaining proper authorization before use. Unauthorized use may be illegal.

Provided "as is," with no warranties. The authors are not liable for any misuse or damages.

_Use at your own risk._

## License

MIT
