# enumx

Subdomain and service enumeration.

## Getting Started

Note: Works on Linux based systems only.

```shell
git clone https://github.com/ayushmanchhabra/enumx
cd enumx
chmod +x ./enum.sh
```

## Usage

```shell
# Internet recon
./scan.sh example.com out.csv --mode=domain --ports=true

# Internal network
./scan.sh 192.168.1.0/24 out.csv --mode=cidr --ports=true

# From file
./scan.sh targets.txt out.csv --mode=file --ports=false
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
