## Build:

```sh
make
```

## Usage:

```sh
sudo ./bin/sniffer -h
Usage: ./bin/sniffer [-d add dump data] [-l log file] [-h]

Options:
  -d     Show data dump (hex/ascii)
  -l     Set the file name for logging
         default ./log.txt
  -h     Print this help message
```

## Example output:

```sh
sudo ./bin/sniffer -d -l sniff_log.txt
Log filename: sniff_log.txt
Dump data enable:
Starting...
TCP : 109   UDP: 22   ICMP : 12   IGMP : 0   L2TP : 0   Others : 0   Total : 154

```

## Example log file:

#### TCP Packet
```sh
########################################################################
Packet #1 (144 bytes read)

Ethernet Header
   |-Destination Address : E0-D5-5E-89-CD-56 
   |-Source Address      : F8-1A-67-4F-34-CA 
   |-Protocol            : 0x0800 

IP Header
   |-IP Version        : 4
   |-IP Header Length  : 5 DWORDS or 20 Bytes
   |-Type Of Service   : 0
   |-IP Total Length   : 130  Bytes(Size of Packet)
   |-Identification    : 44516
   |-TTL      : 114
   |-Protocol : 6
   |-Checksum : 26192
   |-Source IP        : 83.69.223.236
   |-Destination IP   : 192.168.0.103

TCP Header
   |-Source Port      : 44355
   |-Destination Port : 39360
   |-Sequence Number    : 1207256031
   |-Acknowledge Number : 857796528
   |-Header Length      : 5 DWORDS or 20 BYTES
   |-Urgent Flag            : 0
   |-Acknowledgement Flag : 1
   |-Push Flag            : 1
   |-Reset Flag           : 0
   |-Synchronise Flag     : 0
   |-Finish Flag          : 0
   |-Window         : 2053
   |-Checksum       : 7286
   |-Urgent Pointer : 0

                        DATA Dump                         
IP Header
    45 00 00 82 AD E4 40 00 72 06 66 50 53 45 DF EC         E.....@.r.fPSE..
    C0 A8 00 67                                             ...g
TCP Header
    AD 43 99 C0 47 F5 43 DF 33 20 EF B0 50 18 08 05         .C..G.C.3 ..P...
    1C 76 00 00                                             .v..
Data Payload
    17 03 03 00 55 00 00 00 00 00 00 09 7B 95 D9 B8         ....U.......{...
    D1 71 F2 D3 5D 73 FB 9E 9F 90 7E EF 7E 08 1F 0F         .q..]s....~.~...
    46 D3 3C A0 45 C0 7B F0 4D 9F DF 19 71 8D C3 F6         F.<.E.{.M...q...
    6B 87 1A 0F C4 A5 D6 B3 82 C5 C3 F3 70 FF 4A 8B         k...........p.J.
    B8 E9 06 E6 F4 5F 3A 4F 9D D0 FC B9 F1 DB AE 24         ....._:O.......$
    78 DD 5C D4 15 9D 18 15 0C BE                           x.\.......
```


#### UDP Packet

```sh
########################################################################
Packet #10 (71 bytes read)

Ethernet Header
   |-Destination Address : F8-1A-67-4F-34-CA 
   |-Source Address      : E0-D5-5E-89-CD-56 
   |-Protocol            : 0x0800 

IP Header
   |-IP Version        : 4
   |-IP Header Length  : 5 DWORDS or 20 Bytes
   |-Type Of Service   : 0
   |-IP Total Length   : 57  Bytes(Size of Packet)
   |-Identification    : 0
   |-TTL      : 64
   |-Protocol : 17
   |-Checksum : 61314
   |-Source IP        : 192.168.0.103
   |-Destination IP   : 173.194.220.95

UDP Header
   |-Source Port      : 44997
   |-Destination Port : 37
   |-UDP Length       : 37
   |-UDP Checksum     : 19304

                        DATA Dump                         
IP Header
    45 00 00 39 00 00 40 00 40 11 EF 82 C0 A8 00 67         E..9..@.@......g
    AD C2 DC 5F                                             ..._
UDP Header
    AF C5 01 BB 00 25 4B 68                                 .....%Kh
Data Payload
    50 EB A2 E3 B7 B4 BE 1B DA C1 3F E7 94 2E 52 D3         P.........?...R.
    C1 CF 4D 93 20 D4 4F 6D 84 5E 18 AD D7                  ..M. .Om.^...

```

#### ICMP Packet
```sh
########################################################################
Packet #69 (126 bytes read)

Ethernet Header
   |-Destination Address : 00-00-00-00-00-00 
   |-Source Address      : 00-00-00-00-00-00 
   |-Protocol            : 0x0800 

IP Header
   |-IP Version        : 4
   |-IP Header Length  : 5 DWORDS or 20 Bytes
   |-Type Of Service   : 192
   |-IP Total Length   : 112  Bytes(Size of Packet)
   |-Identification    : 6180
   |-TTL      : 64
   |-Protocol : 1
   |-Checksum : 57226
   |-Source IP        : 192.168.0.103
   |-Destination IP   : 192.168.0.103

ICMP Header
   |-Type : 3   |-Code : 1
   |-Checksum : 64766
   |-ID       : 0
   |-Sequence : 0

                        DATA Dump                         
IP Header
    45 C0 00 70 18 24 00 00 40 01 DF 8A C0 A8 00 67         E..p.$..@......g
    C0 A8 00 67                                             ...g
ICMP Header
    03 01 FC FE 00 00 00 00                                 ........
Data Payload
    45 00 00 54 12 68 40 00 40 01 A6 24 C0 A8 00 67         E..T.h@.@..$...g
    C0 A8 00 65 08 00 76 22 00 01 00 01 0A CD 8D 65         ...e..v".......e
    00 00 00 00 28 D6 02 00 00 00 00 00 10 11 12 13         ....(...........
    14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23         ............ !"#
    24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33         $%&'()*+,-./0123
    34 35 36 37                                             4567
```

