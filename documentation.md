# Cyberdeck - Full Documentation

This document explains each module in detail, along with the reasoning behind them.

## Table of Contents

- Modules
    - [Scanning](#scanning)
        - [`-S -ss` - SYN Scan](#-s--ss---syn-scan)
        - [`-S -ts` - TCP Scan](#-s--ts---tcp-scan)
        - [`-S -us` - UDP Scan](#-s--us---udp-scan)
            - [`-S -us -it` - Targeted UDP Scan](#-s--us--it---targeted-udp-scan)
        - [`-S -os` - OS Fingerprinting](#-s--os---os-fingerprinting)
        - [`-S -ns`- Network Scan](#-s--ns---network-scan)
        - [Flags](#flags)
            - [Mandatory Flags](#mandatory-flags)
            - [Optional Flags](#optional-flags)
---

### Scanning

The scanning module provides three main capabilities:

- **Port scanning** using three methods: SYN and TCP scans for TCP ports, and UDP scan for UDP ports.
- **OS fingerprinting**, by evaluating characteristics of the packets sent by the target machine and information retrieved through SNMP.
- **Network scanning**, using ARP and SSDP discovery.

---

#### `-S -ss` - SYN Scan

This scan uses the TCP 3-way handshake to be both effective and stealthy, since it never completes it. The host machine sends a SYN packet to the target, and uses the response to evaluate the state of the port. Because the handshake is never completed, this scan can be less reliable than a full TCP scan when evaluating TCP ports.

The port state is determined by the response:

- Open -> the target replies with a SYN-ACK packet.
- Closed -> the target replies with a RST packet.
- Filtered -> the target does not reply, and the scan times out.

It requires administrator permission, because the socket used is a raw socket, which is not managed by the kernel.

---

#### `-S -ts` - TCP Scan

A TCP scan completes the full TCP 3-way handshake, making it more reliable but less stealthy. The socket used is managed by the kernel, so this scan does **not** require administrator permission.

---

#### `-S -us` - UDP Scan

This scan works by sending UDP headers to UDP ports with no payload attached. It can cover a wide range of ports, but it is not very reliable: services behind UDP ports are highly selective and reactive to the payload of the packet. If the payload does not match what the service expects, it may not reply, giving an inconclusive result, not necessarily because the port is filtered, but because the probe did not match what the service expected.

##### `-S -us -it` - Targeted UDP Scan

This scan covers a significantly smaller set of UDP ports, but instead of sending an empty UDP header, it sends service-specific payloads based on the service typically running behind each port (e.g. a DNS query for port 53). By sending the expected payload, it greatly increases the reliability of the scan.

---

#### `-S -os` - OS Fingerprinting

OS fingerprinting is a two-step process:

1. TCP/IP stack analysis -> it analyzes a response packet from the target (to a SYN sent by the host) and compares certain values (such as TTL and window size) against the expected values for each operating system family.
2. SNMP query -> it sends an SNMP request with the `sysDescr` OID, asking the target for its system description.

The SNMP step is more reliable when it works, but it is harder to obtain: SNMP is protected by a community string (essentially a password), and if the community string does not match the one configured on the target, the target will not reply.

---

#### `-S -ns` - Network Scan

This scan finds all devices on a given network and interface. It also uses a two-step process:

1. SSDP discovery -> the host sends an SSDP request to the multicast address and waits for replies from devices. This works because SSDP (part of UPnP) lets devices announce their existence to one another.
2. ARP scan -> the host sends an ARP request for every possible host IP in the network and waits for replies. It then compares the MAC address of each reply against a vendor database, since the first 6 hexadecimal digits (the OUI) of a MAC address identify the manufacturer.

This scan does not require the target flag, since it scans the whole local network.

---

### Flags

#### Mandatory Flags

##### `-t` - Target

Defines the target machine. It is mandatory for the port scans and OS fingerprinting (but not for the network scan, which scans the whole local network).

---

#### Optional Flags

##### `-it` - isTargeted

As explained in [Targeted UDP Scan](#-s--us--it---targeted-udp-scan), this flag makes the UDP scan a targeted, one scanning only specific ports and sending the service-specific payload for each.

##### `-s` - Stealthiness

Sets how stealthy the scan is by controlling two values: the number of threads (workers) performing the task and the timeout. More workers send more packets per second, and a smaller timeout lets a worker move from one packet to the next faster. A smaller stealthiness value draws less attention and can be more reliable by giving the target more time to reply, but can take significantly longer, especially depending on the port range.

##### `-ps` - Port Range

The range of ports that will be scanned. By default it is (1, 1024), but it can be set to (1, 65535). If the targeted option is used for the UDP scan, this flag is overridden. A smaller port range is faster, but may miss services running on higher ports.

##### `-sc` - Show Closed

If this flag is used, the individual closed ports are shown in the output. This can be useful, but depending on the number of closed ports it can clutter the output. If it is not used, the output shows only the total count of closed ports at the end.

---
