# Wireshark_PCAP_Analysis

<img width="844" height="258" alt="image" src="https://github.com/user-attachments/assets/ba97dd2b-0c41-4c5d-b7b0-992a1a72d614" />

### 1. Capture Overview

| **Property**      | **Value**             |
| ----------------- | --------------------- |
| **First Packet**  | `2021-10-14 06:10:51` |
| **Last Packet**   | `2022-02-17 01:12:33` |
| **Elapsed Time**  | `125 days, 20:01:41`  |
| **Total Packets** | `1,483`               |
| **Total Size**    | `255,216 bytes`       |

**Observation:**
The capture spans **125 days** but contains only **1,483 packets**. This is inconsistent with a continuously monitored production network and strongly suggests that the PCAP is a **compiled/sample capture**, likely created to demonstrate a variety of network **protocols and ports**. This is also consistent with the filename `protocols-and-ports.pcapng`.

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


<img width="1015" height="608" alt="image" src="https://github.com/user-attachments/assets/58375dbe-2482-47f7-aa99-ad3152a46760" />

### 2. Protocol Hierarchy Findings

| **Protocol**            | **Packets / Share** | **Security / Notes**                                             |
| ----------------------- | ------------------: | ---------------------------------------------------------------- |
| **TCP**                 |       85.2% (1,264) | Dominant transport protocol                                      |
| **UDP**                 |         10.8% (160) | —                                                                |
| **POP**                 |           5.1% (76) | **Highest byte share (23.3%)** — one large mail-download session |
| **HTTP**                |           2.4% (36) | —                                                                |
| **FTP**                 |           2.2% (33) | ⚠️ Unencrypted                                                   |
| **Telnet**              |           3.5% (52) | ⚠️ Unencrypted                                                   |
| **Rlogin**              |            0.3% (5) | ⚠️ Unencrypted                                                   |
| **Remote Shell (rsh)**  |            0.1% (1) | ⚠️ Unencrypted                                                   |
| **SSH**                 |            0.1% (1) | Secure remote access                                             |
| **SMTP**                |           1.0% (15) | Email transmission                                               |
| **SNMP**                |           1.3% (20) | Check for plaintext community strings                            |
| **SMB / SMB2**          |           0.9% (13) | File and network resource sharing                                |
| **TFTP**                |           3.4% (50) | ⚠️ Unauthenticated and plaintext                                 |
| **DHCP / DNS / NTP**    |               Minor | Normal infrastructure traffic                                    |
| **802.1Q VLAN Tagging** |                2.2% | Indicates a segmented network design                             |

### Security Observation

The presence of **Telnet, Rlogin, Remote Shell (rsh), FTP, and TFTP** is significant because these protocols can transmit data, including potentially sensitive credentials, in **plaintext**. In a production environment, their use should be considered a **security finding** and remediated by migrating to secure alternatives such as **SSH, SFTP, and HTTPS**.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<img width="1280" height="758" alt="image" src="https://github.com/user-attachments/assets/78691715-af6f-49d0-ac62-2f1dea37b992" />

### 3. Finding #1 — Suspected TCP Port Scan

| **Field**                | **Value**                                                                                                |
| ------------------------ | -------------------------------------------------------------------------------------------------------- |
| **Classification**       | Reconnaissance — Port Scanning                                                                           |
| **Source (Scanner)**     | `192.168.56.102`                                                                                         |
| **Source Port**          | `46729` (constant across all attempts)                                                                   |
| **Destination (Target)** | `192.168.56.101`                                                                                         |
| **Destination Ports**    | Sequential/varied — `21, 22, 23, 53, 80, 110, 111, 113, 135, 139, 143, 443, 445, 5900, 8888`, and others |
| **Confirmed Open Ports** | `22, 23, 80, 111, 135, 139, 445, 5900`                                                                   |

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<img width="1015" height="567" alt="image" src="https://github.com/user-attachments/assets/275d3eac-9192-4dd8-9d6a-f6c36f30d001" />


Trivial File Transfer Protocol - TFTP
Last Updated :
16 Oct, 2025
TFTP stands for Trivial File Transfer Protocol. TFTP is defined as a protocol that is used to transfer a file from a client to a server and vice versa. TFTP is majorly used when no complex interactions are required by the client and server. The service of TFTP is provided by UDP (User Datagram Protocol) and works on port number 69.

IMG-20230812-WA0005
TFTP Protocol
Note: TFTP does not provide security features therefore it is not used in communications that take place over the Internet. Therefore it is used only for the systems that are set up on the local internet. TFTP  requires less amount of memory.  

TFTP Message Formats
There are four types of TFTP Message formats. They are as follows

1. Read Request:
Read Request is also known as Type 1. A read request is used by the client to get a copy of a file from the server. Below is the format of the Read Request

Read Request (1) (2 Octets)
File Name (variable)
0 (1 Octet)
Mode (Variable)
0 (1 Octet)
2. Write Request:
Write Request is also known as Type 2. Write Request is being used by the client for writing a file into the server. Below is the format of the Write Request.

Write Request(2) (2 Octets)
File Name (variable)
0 (1 Octet)
Mode (Variable)
0 (1 Octet)
3. Data
Data is also known as Type 3. Data consists of a portion of a file that is being copied. The data block is of fixed size that is 512 octets. Below is the format of the Data.

Data (3) (2 Octets)
Sequence Number (2 Octets)
Data (Upto 512 octets)
4. Acknowledgement
Acknowledgment is also known as Type 4. The data present at the last in the message consists of the End of File(EOF) where the size is less than 512 octets. This acknowledgment is used by both client and server for acknowledging the received data.

Ack(4) (2 Octets)
Sequence Number (2 Octets)
Working of TFTP
TFTP makes use of port number 69 as it uses User Datagram Protocol (UDP).
When the connection is established successfully between client and server, the client makes a Read Request (RRQ) or
Write Request( WRQ). If a client wants to only read the file it requests RRQ and if the client wants to write some data into a server then it requests for WRQ.
Once the connection is established and a request is made communication of files takes place in the form of small packets. These packets are 512 bytes each.
The server then communicates the packet back to the client and waits until it receives an acknowledgment from the client that the packet has been received.
When the acknowledgment is received from the client side, the server again sends the next packet which is 512 bytes each.
The same steps as mentioned above continue until the last packet is sent by the server to the client.
Comparison of TFTP with FTP
Feature	TFTP	FTP
Protocol	UDP-based	TCP-based
Authentication	None	Username & password required
Reliability	Less reliable	Reliable (TCP error handling)
File Size	Small files	Can handle large files
Use Case	Simple transfers, firmware	General-purpose file transfer

