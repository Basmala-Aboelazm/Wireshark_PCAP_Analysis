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

# Trivial File Transfer Protocol (TFTP)

## Overview

**TFTP (Trivial File Transfer Protocol)** is a simple file transfer protocol used to transfer files between a client and a server.

TFTP is designed for environments where a simple file transfer mechanism is required without the additional features provided by protocols such as FTP.

TFTP operates over **UDP (User Datagram Protocol)** and uses **UDP port 69** for the initial request.

### Key Characteristics

* Uses **UDP** instead of TCP.
* Uses **UDP port 69** for the initial request.
* Does not provide authentication or encryption.
* Uses a simple request/response mechanism.
* Transfers files in small data blocks.
* Commonly used in **local networks** for network device configuration, firmware, and boot files.

> **Security Note:** TFTP does not provide authentication, encryption, or strong security mechanisms. Therefore, it should not be exposed directly to untrusted networks such as the public Internet.

---

# TFTP Message Types

TFTP uses four main message types:

| Message                  | Opcode | Purpose                                 |
| ------------------------ | -----: | --------------------------------------- |
| **RRQ (Read Request)**   |      1 | Requests a file from the server         |
| **WRQ (Write Request)**  |      2 | Sends a file to the server              |
| **DATA**                 |      3 | Transfers a block of file data          |
| **ACK (Acknowledgment)** |      4 | Confirms that a data block was received |

---

# How TFTP Works

The basic TFTP file transfer process is:

### Downloading a File

1. The client sends an **RRQ (Read Request)** to the server on UDP port `69`.
2. The server responds with the first **DATA** block.
3. The client sends an **ACK** for that block.
4. The server sends the next DATA block.
5. The client acknowledges each received block.
6. The process continues until the entire file is transferred.
7. The final DATA packet contains **less than 512 bytes**, indicating the end of the transfer.

### Uploading a File

1. The client sends a **WRQ (Write Request)** to the server.
2. The server responds with an **ACK**.
3. The client sends the first DATA block.
4. The server acknowledges the block.
5. The client continues sending DATA blocks and waits for ACKs.
6. The process continues until the complete file is uploaded.

---

<img width="1015" height="567" alt="image" src="https://github.com/user-attachments/assets/275d3eac-9192-4dd8-9d6a-f6c36f30d001" />

<img width="878" height="221" alt="image" src="https://github.com/user-attachments/assets/4d89f08c-4f62-4a29-857c-1385c4e2928b" />

