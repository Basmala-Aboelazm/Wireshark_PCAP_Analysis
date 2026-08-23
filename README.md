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
| **FTP**                 |           2.2% (33) | Unencrypted                                                   |
| **Telnet**              |           3.5% (52) | Unencrypted                                                   |
| **Rlogin**              |            0.3% (5) | Unencrypted                                                   |
| **Remote Shell (rsh)**  |            0.1% (1) | Unencrypted                                                   |
| **SSH**                 |            0.1% (1) | Secure remote access                                             |
| **SMTP**                |           1.0% (15) | Email transmission                                               |
| **SNMP**                |           1.3% (20) | Check for plaintext community strings                            |
| **SMB / SMB2**          |           0.9% (13) | File and network resource sharing                                |
| **TFTP**                |           3.4% (50) | Unauthenticated and plaintext                                 |
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


### 4. Finding #2 — TFTP File Transfer

**Classification:** Benign / Expected Traffic

| Field          | Value              |
| -------------- | ------------------ |
| Client         | `192.168.0.253`    |
| Server         | `192.168.0.10`     |
| File Requested | `rfc1350.txt`      |
| Transfer Mode  | `octet`            |
| Transfer Range | Block 1 → Block 49 |

**Evidence:**

* The traffic begins with a **TFTP Read Request (RRQ)** sent from `192.168.0.253` to the TFTP server at `192.168.0.10`.
* The server then responds by sending **DATA blocks sequentially**, starting from Block 1.
* The transfer continues through **Block 49**, with the expected acknowledgment (**ACK**) exchanged between the client and server.
* The observed flow follows the normal TFTP pattern.
* No obvious anomalies, retransmissions, or errors were observed in the reviewed traffic.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Simple Network Management Protocol (SNMP)

## Overview

**SNMP (Simple Network Management Protocol)** is an **application-layer protocol** used to monitor and manage network-connected devices in IP networks.

SNMP allows a **Network Management System (NMS)** or **SNMP Manager** to communicate with an **SNMP Agent** running on devices such as:

* Routers
* Switches
* Servers
* Firewalls
* Printers
* Access Points

SNMP is mainly used to **monitor network devices, collect information, detect faults, and manage device configurations**.

### SNMP Ports

SNMP uses **UDP**:

| Port        | Purpose                        |
| ----------- | ------------------------------ |
| **UDP 161** | SNMP requests and responses    |
| **UDP 162** | SNMP Traps and Inform messages |

---

# SNMP Architecture

SNMP mainly consists of two components:

### 1. SNMP Manager

The **SNMP Manager** is responsible for monitoring and managing network devices.

It can send requests such as:

* GetRequest
* GetNextRequest
* SetRequest

### 2. SNMP Agent

The **SNMP Agent** runs on the managed device and collects information about the device.

The Agent responds to requests from the Manager and can also send notifications when specific events occur.

```text
        SNMP Manager / NMS
               |
        UDP 161 / 162
               |
        SNMP Agent
               |
      Managed Network Device
```

---

# SNMP Messages

## 1. GetRequest

A **GetRequest** is used by the SNMP Manager to retrieve the value of a specific object from the SNMP Agent.

### Example

The Manager may request the current CPU utilization of a router.

```text
Manager → Agent: GetRequest
Agent → Manager: Response
```

---

## 2. GetNextRequest

A **GetNextRequest** is used to retrieve the next object in the **MIB (Management Information Base)**.

It is commonly used when walking through tables or retrieving sequential OIDs.

```text
Manager → Agent: GetNextRequest
Agent → Manager: Response
```

---

## 3. SetRequest

A **SetRequest** is used by the SNMP Manager to modify the value of an object on the SNMP Agent.

For example, it can be used to change a configurable parameter on a network device.

```text
Manager → Agent: SetRequest
Agent → Manager: Response
```

---

## 4. Response

A **Response** message is sent by the SNMP Agent in reply to a request from the Manager.

It can contain:

* The requested value
* The newly configured value
* An error message if the request failed

```text
Manager → Agent: GetRequest
Agent → Manager: Response
```

---

## 5. Trap

A **Trap** is an unsolicited notification sent by the SNMP Agent to the SNMP Manager when a specific event occurs.

The Manager does **not** need to request the Trap first.

### Example

If a network interface goes down:

```text
Agent → Manager: Trap
Interface Down
```

Traps are normally sent using **UDP port 162**.

> **Important:** A Trap does not require an acknowledgment from the Manager.

---

## 6. InformRequest

**InformRequest** was introduced in **SNMPv2c**.

It is similar to a Trap because it sends an unsolicited notification. However, an InformRequest **requires an acknowledgment** from the receiver.

```text
Agent → Manager: InformRequest
Manager → Agent: Response (Acknowledgment)
```

---

# Characteristics of SNMP

* Used for **network monitoring and management**.
* Helps detect **network and device faults**.
* Collects information such as CPU usage, memory utilization, interface status, and network traffic.
* Can be used to **configure remote devices** using SetRequest.
* Provides a standardized way to manage devices from different vendors.
* Uses **UDP** for communication.
* Supports **SNMPv1, SNMPv2c, and SNMPv3**.

---


<img width="1246" height="243" alt="image" src="https://github.com/user-attachments/assets/3b3811aa-66c5-414c-a221-5e339f5434e1" />





### SNMP Traffic Analysis

**Classification:** Benign / Expected SNMP Monitoring Traffic

#### Endpoints

* **`172.31.19.54`** → Sends **GetRequest** messages. This is the **NMS (Network Management System) / Monitoring Station**.
* **`172.31.19.73`** → Sends **GetResponse** messages. This is the **SNMP Agent / Monitored Device**.

#### Observed Traffic Pattern

```text
100: .54 → .73  GetRequest   1.3.6.1.2.1.1.2.0
101: .73 → .54  GetResponse  1.3.6.1.2.1.1.2.0

102: .54 → .73  GetRequest   1.3.6.1.2.1.1.5.0
                             1.3.6.1.2.1.1.6.0

103: .73 → .54  GetResponse  ...

...

112-119: The same request/response sequence repeats
```

#### Analysis

* The communication follows the expected **SNMP Manager → Agent → Manager** pattern.
* `172.31.19.54` repeatedly queries `172.31.19.73` using **GetRequest** messages.
* `172.31.19.73` responds to each request with a corresponding **GetResponse**.
* The requested OIDs remain consistent across the observed requests.
* The sequence from packets **100–111** is repeated again starting at **packet 112**, with the same OIDs and order.
* This repeated behavior indicates a **periodic polling cycle**, which is typical of an NMS continuously monitoring a network device.
* The polling interval appears to be approximately **one second** in the analyzed traffic.

#### Conclusion

The observed traffic is **consistent with legitimate SNMP monitoring activity**. The repeated GetRequest/GetResponse pattern indicates that `172.31.19.54` is periodically polling `172.31.19.73` to collect management information.

-----


<img width="1246" height="154" alt="image" src="https://github.com/user-attachments/assets/355bf82f-63c6-48cb-b10e-6c825bb57ba5" />


## Finding #3 — LDAP Bind/Search Activity (Localhost)

**Classification:** Benign / Synthetic Test Traffic

| Field         | Value                               |
| ------------- | ----------------------------------- |
| Source        | `127.0.0.1` (localhost)             |
| Destination   | `127.0.0.1` (localhost)             |
| Port          | `389` (LDAP)                        |
| Bind DN       | `<ROOT>`                            |
| Bind Type     | Simple Bind                         |
| Bind Result   | Success                             |
| Search Scope  | `wholeSubtree`                      |
| Search Result | `noSuchObject` — 0 results returned |

### Evidence

```text
128-130: TCP 3-way handshake (40848 → 389)
131:     bindRequest(1) "<ROOT>" simple
133:     bindResponse(1) success
135:     searchRequest(2) "<ROOT>" wholeSubtree
136:     searchResDone(2) noSuchObject [0 results]
137:     unbindRequest(3)
138-140: TCP teardown
```

### Analysis

The observed traffic represents an LDAP bind followed by a directory search over the local host.

A potential question during the investigation was whether this activity could represent an attacker attempting to obtain a root or administrator password through LDAP.

The traffic was classified as **benign / synthetic test traffic** for the following reasons:

1. **`<ROOT>` is not necessarily a username or root account.**
   In LDAP, a root search base refers to the top of the directory tree. The literal `<ROOT>` value, especially when presented as a placeholder, strongly suggests sample or test traffic rather than a real production directory entry.

2. **No evidence of credential compromise was observed.**
   The bind operation returned `success`, but the capture does not provide evidence that credentials were successfully extracted or exfiltrated.

3. **The LDAP search returned no results.**
   The server returned `noSuchObject`, with **0 results**, meaning that no directory information such as users, groups, or other objects was successfully retrieved.

4. **Source and destination are both `127.0.0.1`.**
   This indicates communication between processes on the same host rather than traffic between an external attacker and a remote LDAP server.

### Conclusion

The traffic is consistent with a **local LDAP bind and search test**, likely related to development, testing, or protocol demonstration activity rather than an active attack.

**Final Classification: Benign / Synthetic Test Traffic**

---


<img width="1245" height="27" alt="image" src="https://github.com/user-attachments/assets/bdccb4a1-a231-43d0-946b-9d1359624ddb" />




## Finding #4 — DNS Query and Response Activity

**Classification:** Benign / Expected DNS Traffic

| Field            | Value              |
| ---------------- | ------------------ |
| Client           | `10.10.1.4`        |
| DNS Server       | `10.10.1.1`        |
| Query Type       | `A` (IPv4 Address) |
| Requested Domain | `mail.patriots.in` |
| Resolved IP      | `74.53.140.153`    |

### Evidence

```text
Packet 141:
10.10.1.4 → 10.10.1.1
Standard query 0x7956
A mail.patriots.in

Packet 142:
10.10.1.1 → 10.10.1.4
Standard query response 0x7956

A mail.patriots.in → CNAME patriots.in
A patriots.in → 74.53.140.153
NS ns2.patriots...
```

### Analysis

1. **DNS Query**
   Host `10.10.1.4` sent an **A record query** to the DNS server `10.10.1.1`, requesting the IPv4 address associated with `mail.patriots.in`.

2. **DNS Response**
   The DNS server successfully responded with the requested DNS information.

3. **CNAME Record**
   The response indicates that `mail.patriots.in` is a **CNAME (Canonical Name)** pointing to `patriots.in`.

4. **A Record**
   The domain `patriots.in` resolves to the IPv4 address:

   ```text
   74.53.140.153
   ```

5. **NS Record**
   The response also contains an **NS (Name Server)** record identifying an authoritative name server for the domain.

---


























