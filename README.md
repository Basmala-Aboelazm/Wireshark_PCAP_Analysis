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

## 1. Read Request (RRQ)

A **Read Request** is used when the client wants to download a file from the TFTP server.

### Format

```text
| Opcode (1) | Filename | 0 | Mode | 0 |
```

* **Opcode:** `1`
* **Filename:** Name of the requested file.
* **Mode:** Transfer mode, commonly `octet`.
* `0`: Null byte used to separate fields.

### Example

```text
Client → Server: RRQ "config.txt", mode "octet"
```

---

## 2. Write Request (WRQ)

A **Write Request** is used when the client wants to upload a file to the TFTP server.

### Format

```text
| Opcode (2) | Filename | 0 | Mode | 0 |
```

* **Opcode:** `2`
* **Filename:** Name of the file to be uploaded.
* **Mode:** Transfer mode, commonly `octet`.

### Example

```text
Client → Server: WRQ "backup.cfg", mode "octet"
```

---

## 3. Data (DATA)

The **DATA** message carries a portion of the file being transferred.

### Format

```text
| Opcode (3) | Block Number | Data |
```

* **Opcode:** `3`
* **Block Number:** Identifies the current data block.
* **Data:** Up to **512 bytes** in traditional TFTP.

Each data block is acknowledged before the next block is sent.

---

## 4. Acknowledgment (ACK)

The **ACK** message is used to confirm that a DATA block or request has been successfully received.

### Format

```text
| Opcode (4) | Block Number |
```

* **Opcode:** `4`
* **Block Number:** Identifies the block being acknowledged.

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

# TFTP Ports

TFTP uses **UDP port 69** for the initial request.

After the request is accepted, the actual file transfer normally continues using a **new UDP transfer identifier (TID)** rather than continuing to use port 69 for every packet.

This allows multiple TFTP transfers to be handled independently.

---

# TFTP vs FTP

| Feature            | TFTP                                           | FTP                         |
| ------------------ | ---------------------------------------------- | --------------------------- |
| Transport Protocol | UDP                                            | TCP                         |
| Default Port       | UDP 69                                         | TCP 21                      |
| Authentication     | No                                             | Yes                         |
| Encryption         | No                                             | No by default               |
| Reliability        | Implemented by TFTP using ACKs/retransmissions | Provided by TCP             |
| Complexity         | Simple                                         | More complex                |
| File Transfer      | Basic file transfer                            | Full-featured file transfer |
| Common Uses        | Network boot, configuration, firmware          | General file transfer       |

---

# Common Uses of TFTP

TFTP is commonly used in controlled network environments for:

* **Cisco/network device configuration backups**
* **Firmware transfers**
* **Network booting (PXE)**
* **Boot files**
* **Configuration files**
* Simple file transfers within trusted networks

---

# Advantages

* Simple protocol with low overhead.
* Requires relatively few system resources.
* Easy to implement.
* Useful for network booting and device configuration.
* Does not require a complex authentication mechanism.

# Disadvantages

* No authentication.
* No encryption.
* Not suitable for transferring sensitive information over untrusted networks.
* Limited functionality compared with FTP.
* Uses UDP, so reliability must be handled by the TFTP protocol itself.

---

## Summary

**TFTP is a lightweight file transfer protocol that uses UDP and is designed for simple file transfers.** It uses RRQ and WRQ to initiate transfers, DATA packets to transfer files, and ACK packets to confirm successful delivery.

Because TFTP provides **no authentication or encryption**, it is mainly suitable for controlled and trusted network environments such as **network device configuration, firmware updates, and network booting**.

