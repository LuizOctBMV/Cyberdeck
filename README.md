<a id="readme-top"></a>

<div align="center">

# Cyberdeck

**A cybersecurity toolkit built from scratch in Python with no external libraries**

![Python](https://img.shields.io/badge/python-3.x-blue?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-black?style=for-the-badge&logo=linux&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

</div>

## Table of Contents

1. [Disclaimer](#disclaimer)
2. [About The Project](#about-the-project)
   - [Modules](#modules)
   - [Built With](#built-with)
3. [Getting Started](#getting-started)
   - [Prerequisites](#prerequisites)
   - [Installation](#installation)
4. [Usage](#usage)
5. [How It Works](#how-it-works)
6. [Roadmap](#roadmap)
7. [License](#license)
8. [Contact](#contact)
8. [Acknowledgements](#acknowledgements)

## Disclaimer

This toolkit is intended for **educational purposes and authorized security testing only**. Only use it against networks, devices, and systems that you own or have explicit written permission to test. Unauthorized use may be illegal in your jurisdiction and is entirely your responsibility. 
**The author assumes no liability for misuse**.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## About The Project

Cyberdeck is a command-line cybersecurity toolkit, composed of many (in the future hopefully, for now just one) useful tools in cybersecurity in a single place.

The main idea I had when developing this tool is to allow me to understand the underlying parts of many popular cybersecurity tools, without using any external libraries that would do the work for me and therefore reduce my opportunity to learn. It taught me a lot, way more than I expected, and if you are reading this you should definitely try it yourself too.



### Modules

1. **Scanning**
  - **Port Scanning** ->  scan TCP and UDP ports using SYN, TCP and UDP scans. Having the possibility of choosing desired speed and ports to be scanned.
  - **OS Fingerprinting** -> infers the target's operating system family by analyzing TCP/IP stack characteristics (TTL, window size, TCP options) and complemented by SNMP `sysDescr` when available.
  - **Network Discovery** -> enumerates devices on the local network via ARP scanning and SSDP/UPnP.

 More modules will be added check [roadmap](#roadmap)!

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

- Python 3 -> **standard library** only, **no external dependencies**.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

### Prerequisites

- **Python 3.x**
- **Linux**
- **Root privileges** (raw sockets require administrator privilege)

### Installation

1. Clone the repository
```sh
   git clone https://github.com/LuizOctBMV/Cyberdeck.git
```
2. Enter the directory
```sh
   cd cyberdeck
```
3. Download the [MAC vendor database](https://maclookup.app/downloads/csv-database), which is used for vendor lookup in the network scan from maclookup.app in CSV format, and save it as mac-vendors-export.csv on the folder ./wordlists in the project directory. 


4. Run it 
```sh
   sudo python3 cyberdeck.py --help
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

Cyberdeck works both via command-line flags and an interactive menu (run with no arguments for the guided mode).

**SYN scan** of a target's ports:
```sh
sudo python3 cyberdeck.py -S -ss -t 192.168.1.1
```

**Targeted UDP scan** (uses protocol-specific payloads for reliable detection):
```sh
sudo python3 cyberdeck.py -S -us -it -t 192.168.1.1
```

**OS fingerprint** of a target:
```sh
sudo python3 cyberdeck.py -S -os -t 192.168.1.1
```

**Network discovery** (find all devices on your local network):
```sh
sudo python3 cyberdeck.py -S -ns
```

**Interactive mode** (guided prompts):
```sh
sudo python3 cyberdeck.py
```

Run `--help` to see all available flags and options.

### Example Output

Network discovery -> finds every device on the local network with its MAC address and vendor:

```
└─$ time sudo python3 cyberdeck.py -S -ns

   ▄████▄▓██   ██▓ ▄▄▄▄   ▓█████  ██▀███  ▓█████▄ ▓█████  ▄████▄   ██ ▄█▀
  ▒██▀ ▀█ ▒██  ██▒▓█████▄ ▓█   ▀ ▓██ ▒ ██▒▒██▀ ██▌▓█   ▀ ▒██▀ ▀█   ██▄█▒ 
  ▒▓█    ▄ ▒██ ██░▒██▒ ▄██▒███   ▓██ ░▄█ ▒░██   █▌▒███   ▒▓█    ▄ ▓███▄░ 
  ▒▓▓▄ ▄██▒░ ▐██▓░▒██░█▀  ▒▓█  ▄ ▒██▀▀█▄  ░▓█▄   ▌▒▓█  ▄ ▒▓▓▄ ▄██▒▓██ █▄ 
  ▒ ▓███▀ ░░ ██▒▓░░▓█  ▀█▓░▒████▒░██▓ ▒██▒░▒████▓ ░▒████▒▒ ▓███▀ ░▒██▒ █▄
  ░ ░▒ ▒  ░ ██▒▒▒ ░▒▓███▀▒░░ ▒░ ░░ ▒▓ ░▒▓░ ▒▒▓  ▒ ░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▒ ▓▒
    ░  ▒  ▓██ ░▒░ ▒░▒   ░  ░ ░  ░  ░▒ ░ ▒░ ░ ▒  ▒  ░ ░  ░  ░  ▒   ░ ░▒ ▒░
  ░       ▒ ▒ ░░   ░    ░    ░     ░░   ░  ░ ░  ░    ░   ░        ░ ░░ ░ 
  ░ ░     ░ ░      ░         ░  ░   ░        ░       ░  ░░ ░      ░  ░   
  ░       ░ ░           ░                  ░             ░               
  


SSDP Results: 

| Device: eero                                                     |
| Device Type: urn:schemas-upnp-org:device:InternetGatewayDevice:1 |
| Manufacturer: eero inc.                                          |
| Model Name: eero                                                 |


ARP Results: 

MAC Address         IP Address        Vendor
D4:3F:32:xx:xx:xx   192.168.4.1     eero inc.
DC:56:7B:xx:xx:xx   192.168.4.2     CLOUD NETWORK TECHNOLOGY SINGAPORE PTE. LTD.
B8:B4:09:xx:xx:xx   192.168.4.3     Samsung Electronics Co.,Ltd
AA:BB:CC:xx:xx:xx   192.168.4.4     Raspberry Pi (Trading) Ltd


real    13.05s
user    0.01s
sys     0.00s
cpu     0%

```
Targeted UDP scan -> sends packets to common UDP ports with a specific payload:
```
└─$ time sudo python3 cyberdeck.py -S -Us -t 192.168.4.1 -s 4 -it

   ▄████▄▓██   ██▓ ▄▄▄▄   ▓█████  ██▀███  ▓█████▄ ▓█████  ▄████▄   ██ ▄█▀
  ▒██▀ ▀█ ▒██  ██▒▓█████▄ ▓█   ▀ ▓██ ▒ ██▒▒██▀ ██▌▓█   ▀ ▒██▀ ▀█   ██▄█▒ 
  ▒▓█    ▄ ▒██ ██░▒██▒ ▄██▒███   ▓██ ░▄█ ▒░██   █▌▒███   ▒▓█    ▄ ▓███▄░ 
  ▒▓▓▄ ▄██▒░ ▐██▓░▒██░█▀  ▒▓█  ▄ ▒██▀▀█▄  ░▓█▄   ▌▒▓█  ▄ ▒▓▓▄ ▄██▒▓██ █▄ 
  ▒ ▓███▀ ░░ ██▒▓░░▓█  ▀█▓░▒████▒░██▓ ▒██▒░▒████▓ ░▒████▒▒ ▓███▀ ░▒██▒ █▄
  ░ ░▒ ▒  ░ ██▒▒▒ ░▒▓███▀▒░░ ▒░ ░░ ▒▓ ░▒▓░ ▒▒▓  ▒ ░░ ▒░ ░░ ░▒ ▒  ░▒ ▒▒ ▓▒
    ░  ▒  ▓██ ░▒░ ▒░▒   ░  ░ ░  ░  ░▒ ░ ▒░ ░ ▒  ▒  ░ ░  ░  ░  ▒   ░ ░▒ ▒░
  ░       ▒ ▒ ░░   ░    ░    ░     ░░   ░  ░ ░  ░    ░   ░        ░ ░░ ░ 
  ░ ░     ░ ░      ░         ░  ░   ░        ░       ░  ░░ ░      ░  ░   
  ░       ░ ░           ░                  ░             ░               
  

port          state
53|udp  open
67|udp  open
123|udp  open

4 ports closed and 0 ports filtered

real    0.14s
user    0.01s
sys     0.01s
cpu     11%
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## How It Works

Check the [documentation](documentation.md)! 

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Roadmap

For now there is only the scanning module, but I wish to add many more:

- [ ] mDNS discovery for Network Scan
- [ ] Analysis of RST packet for OS fingerprinting
- [ ] Hashing and hash-related utilities


<p align="right">(<a href="#readme-top">back to top</a>)</p>

## License

Distributed under the MIT License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contact

Luiz Octávio - [LinkedIn](https://www.linkedin.com/in/luiz-octavio-bartolomeu/)

Project Link: [https://github.com/LuizOctBMV/Cyberdeck.git](https://github.com/LuizOctBMV/Cyberdeck.git)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Acknowledgements

These are some of the websites I used that can be used for someone wanting to do the same.

- [GeeksforGeeks](https://www.geeksforgeeks.org/) -> For the structure of the different headers used
- [Wikipedia](https://en.wikipedia.org/wiki/TCP/IP_stack_fingerprinting) -> For the information to be analyzed on the OS fingerprinting process
- **RFCs** -> This is a more general source, but it was used mainly when crafting the specific payloads for the UDP scan
- [maclookup.app](https://maclookup.app/) -> MAC address vendor database (sourced from the IEEE registry).
