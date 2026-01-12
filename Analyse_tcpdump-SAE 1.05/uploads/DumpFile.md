# Network traffic analysis report

## General summary
Here is a summary of the main elements detected in the capture:

### Suspected port scan
- ns1.lan.rt seems to be testing many ports on BP-Linux8.

### Suspected denial of service (DoS)
- A large part of the traffic is directed to BP-Linux8, which may indicate an attempt to overload it.
- A large part of the traffic is directed to host 184.107.43.74, which may indicate an attempt to overload it.

### Suspected SYN flood
- The number of SYN packets to host 184.107.43.74 is very high compared to the rest of the traffic.

### Presence of very talkative sources
- BP-Linux8 sends a large number of packets or contacts many different destinations.
- 190-0-175-100.gba.solunet.com.ar sends a large number of packets or contacts many different destinations.
- par21s04-in-f4.1e100.net sends a large number of packets or contacts many different destinations.
- par10s38-in-f3.1e100.net sends a large number of packets or contacts many different destinations.
- par21s23-in-f3.1e100.net sends a large number of packets or contacts many different destinations.
- par21s17-in-f1.1e100.net sends a large number of packets or contacts many different destinations.
- mauves.univ-st-etienne.fr sends a large number of packets or contacts many different destinations.
- www.aggloroanne.fr sends a large number of packets or contacts many different destinations.

These observations must be interpreted in the context of the network:
- they may correspond to real attacks,
- or to legitimate but very active applications (backups, updates, etc.).

## General information about the capture

| Element | Value |
|---|---|
| Packets analysed | 9629 |
| Total volume | 6248051 bytes |
| Capture duration | 43.300 s |
| Average rate | 222.378 packets/s |
| Total SYN packets | 2078 |

## Protocol distribution

| Protocol | Packets |
|---|---:|
| TCP | 9415 |
| UDP | 124 |
| ICMP | 72 |
| OTHER | 18 |

## TCP connection behaviour

| Flags | Packets |
|---|---:|
| . | 5955 |
| S | 2039 |
| P. | 1348 |
| S. | 39 |
| F. | 34 |

## SYN packets by destination

| Destination | SYN | Total | Ratio |
|---|---:|---:|---:|
| 184.107.43.74 | 2000 | 2000 | 1.00 |
| BP-Linux8 | 39 | 5037 | 0.01 |
| mauves.univ-st-etienne.fr | 7 | 744 | 0.01 |
| par21s17-in-f1.1e100.net | 6 | 176 | 0.03 |
| par21s23-in-f3.1e100.net | 6 | 182 | 0.03 |
| www.aggloroanne.fr | 6 | 712 | 0.01 |
| par21s05-in-f131.1e100.net | 5 | 36 | 0.14 |
| par21s20-in-f14.1e100.net | 2 | 53 | 0.04 |
| par21s17-in-f14.1e100.net | 2 | 56 | 0.04 |
| 201.181.244.35.bc.googleusercontent.com | 1 | 16 | 0.06 |
| par10s38-in-f3.1e100.net | 1 | 255 | 0.00 |
| par21s18-in-f3.1e100.net | 1 | 16 | 0.06 |
| par10s40-in-f3.1e100.net | 1 | 17 | 0.06 |
| par21s11-in-f10.1e100.net | 1 | 25 | 0.04 |

## Main source hosts

| Source | Packets |
|---|---:|
| BP-Linux8 | 2592 |
| 190-0-175-100.gba.solunet.com.ar | 2000 |
| mauves.univ-st-etienne.fr | 1680 |
| www.aggloroanne.fr | 1478 |
| par10s38-in-f3.1e100.net | 827 |
| par21s04-in-f4.1e100.net | 218 |
| par21s23-in-f3.1e100.net | 204 |
| par21s17-in-f1.1e100.net | 180 |
| ns1.lan.rt | 71 |
| 192.168.190.130 | 58 |

## Main destination hosts

| Destination | Packets |
|---|---:|
| BP-Linux8 | 5037 |
| 184.107.43.74 | 2000 |
| mauves.univ-st-etienne.fr | 744 |
| www.aggloroanne.fr | 712 |
| par10s38-in-f3.1e100.net | 255 |
| par21s23-in-f3.1e100.net | 182 |
| par21s17-in-f1.1e100.net | 176 |
| par21s04-in-f4.1e100.net | 76 |
| ns1.lan.rt | 71 |
| par21s17-in-f14.1e100.net | 56 |

## Most used destination ports

| Port | Packets |
|---|---:|
| https | 2386 |
| http | 2046 |
| 34862 | 827 |
| 40682 | 399 |
| 40678 | 382 |
| 53324 | 357 |
| 40684 | 299 |
| 40680 | 295 |
| 53325 | 255 |
| 53328 | 244 |

## Flow table

A flow = (source, source port, destination, destination port, protocol). Duration is computed between first and last packet seen.

| Source | Src port | Destination | Dst port | Proto | Packets | Bytes | Duration (s) |
|---|---|---|---|---|---:|---:|---:|
| par10s38-in-f3.1e100.net | https | BP-Linux8 | 34862 | TCP | 827 | 877867 | 6.861 |
| mauves.univ-st-etienne.fr | https | BP-Linux8 | 40682 | TCP | 399 | 555111 | 11.808 |
| mauves.univ-st-etienne.fr | https | BP-Linux8 | 40678 | TCP | 382 | 533277 | 11.971 |
| www.aggloroanne.fr | https | BP-Linux8 | 53324 | TCP | 357 | 489893 | 2.255 |
| mauves.univ-st-etienne.fr | https | BP-Linux8 | 40684 | TCP | 299 | 416321 | 11.767 |
| mauves.univ-st-etienne.fr | https | BP-Linux8 | 40680 | TCP | 295 | 411283 | 11.779 |
| www.aggloroanne.fr | https | BP-Linux8 | 53325 | TCP | 255 | 352964 | 1.572 |
| BP-Linux8 | 34862 | par10s38-in-f3.1e100.net | https | TCP | 255 | 15111 | 6.857 |
| www.aggloroanne.fr | https | BP-Linux8 | 53328 | TCP | 244 | 336631 | 1.564 |
| www.aggloroanne.fr | https | BP-Linux8 | 53329 | TCP | 230 | 320706 | 1.561 |
| par21s04-in-f4.1e100.net | https | BP-Linux8 | 41767 | TCP | 218 | 204457 | 24.091 |
| www.aggloroanne.fr | https | BP-Linux8 | 53326 | TCP | 214 | 293708 | 1.571 |
| www.aggloroanne.fr | https | BP-Linux8 | 53327 | TCP | 178 | 243909 | 1.570 |
| mauves.univ-st-etienne.fr | https | BP-Linux8 | 40679 | TCP | 161 | 219400 | 11.781 |
| BP-Linux8 | 40678 | mauves.univ-st-etienne.fr | https | TCP | 158 | 5306 | 11.971 |
| BP-Linux8 | 53328 | www.aggloroanne.fr | https | TCP | 156 | 5812 | 1.582 |
| BP-Linux8 | 40682 | mauves.univ-st-etienne.fr | https | TCP | 149 | 3731 | 11.809 |
| BP-Linux8 | 53329 | www.aggloroanne.fr | https | TCP | 147 | 6267 | 1.580 |
| mauves.univ-st-etienne.fr | https | BP-Linux8 | 40683 | TCP | 118 | 157452 | 11.807 |
| BP-Linux8 | 40684 | mauves.univ-st-etienne.fr | https | TCP | 118 | 3400 | 11.768 |
| BP-Linux8 | 40680 | mauves.univ-st-etienne.fr | https | TCP | 114 | 3641 | 11.776 |
| BP-Linux8 | 53324 | www.aggloroanne.fr | https | TCP | 112 | 7914 | 2.274 |
| BP-Linux8 | 53326 | www.aggloroanne.fr | https | TCP | 105 | 5807 | 1.590 |
| BP-Linux8 | 53325 | www.aggloroanne.fr | https | TCP | 99 | 6810 | 1.591 |
| BP-Linux8 | 53327 | www.aggloroanne.fr | https | TCP | 93 | 5788 | 1.589 |

## Detected alerts

| Type | Detail |
|---|---|
| PORTSCAN | ns1.lan.rt is testing 53 ports on BP-Linux8. |
| POSSIBLE_DOS | DoS on BP-Linux8: 5037 packets (52.3%). |
| POSSIBLE_DOS | DoS on host 184.107.43.74: 2000 packets (20.8%). |
| NOISY_SOURCE | BP-Linux8: 32 dests, 2592 packets. |
| NOISY_SOURCE | 190-0-175-100.gba.solunet.com.ar: 1 dests, 2000 packets. |
| NOISY_SOURCE | par21s04-in-f4.1e100.net: 1 dests, 218 packets. |
| NOISY_SOURCE | par10s38-in-f3.1e100.net: 1 dests, 827 packets. |
| NOISY_SOURCE | par21s23-in-f3.1e100.net: 1 dests, 204 packets. |
| NOISY_SOURCE | par21s17-in-f1.1e100.net: 1 dests, 180 packets. |
| NOISY_SOURCE | mauves.univ-st-etienne.fr: 1 dests, 1680 packets. |
| NOISY_SOURCE | www.aggloroanne.fr: 1 dests, 1478 packets. |
| POSSIBLE_SYN_FLOOD | SYN flood on host 184.107.43.74: 2000 SYN (100.0%). |

## Main suspicious activities

- Port scan from ns1.lan.rt to BP-Linux8.
- Possible DoS to BP-Linux8 with 5037 packets (52.3% of traffic).