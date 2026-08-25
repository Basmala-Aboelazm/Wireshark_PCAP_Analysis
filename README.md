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

---

<img width="1021" height="44" alt="image" src="https://github.com/user-attachments/assets/f16127c2-9b4d-4324-8c2b-5a93207366cc" />


## Finding #5 — DHCP DORA Process

**Classification:** Benign / Expected DHCP Traffic

### Endpoints

| Endpoint          | Role                               |
| ----------------- | ---------------------------------- |
| `0.0.0.0`         | DHCP client with no IP address yet |
| `255.255.255.255` | Local network broadcast address    |
| `192.168.0.1`     | DHCP Server                        |
| `192.168.0.10`    | IP address offered to the client   |

### Evidence

```text
Packet 144:
0.0.0.0 → 255.255.255.255
DHCP Discover
Transaction ID: 0x3d1d

Packet 145:
192.168.0.1 → 192.168.0.10
DHCP Offer
Transaction ID: 0x3d1d

Packet 146:
0.0.0.0 → 255.255.255.255
DHCP Request
Transaction ID: 0x3d1e

Packet 147:
192.168.0.1 → 192.168.0.10
DHCP ACK
Transaction ID: 0x3d1e
```

### Analysis — DHCP DORA Process

The observed traffic represents the standard **DHCP DORA process**, which consists of four steps:

| Step         | Packet | Description                                                                 |
| ------------ | -----: | --------------------------------------------------------------------------- |
| **Discover** |    144 | The client broadcasts a request because it does not have an IP address yet. |
| **Offer**    |    145 | The DHCP server offers the client the IP address `192.168.0.10`.            |
| **Request**  |    146 | The client broadcasts a request to accept the offered IP address.           |
| **ACK**      |    147 | The DHCP server confirms the IP assignment.                                 |

### DHCP Flow

```text
Client                         DHCP Server
  |                                 |
  | DHCP Discover                   |
  |-------------------------------> |
  |                                 |
  | DHCP Offer                      |
  | <-------------------------------|
  |      192.168.0.10               |
  |                                 |
  | DHCP Request                    |
  |-------------------------------> |
  |                                 |
  | DHCP ACK                        |
  | <-------------------------------|
  |      IP assignment confirmed    |
```

### Conclusion

The observed traffic follows the expected **DHCP DORA sequence** and does not show any obvious malicious behavior.

The client initially uses `0.0.0.0` because it does not yet have a valid IP address, while `255.255.255.255` is used for broadcasting the DHCP messages on the local network.

**Final Classification: Benign / Expected DHCP Traffic**

### When DHCP Traffic Should Be Investigated

Although this traffic is normal, the following patterns may indicate suspicious activity:

* **Rogue DHCP Server:** An unauthorized DHCP server responds to client requests and provides potentially malicious gateway or DNS settings.
* **DHCP Starvation:** A large number of DHCP Discover requests are generated using spoofed MAC addresses to exhaust the available IP address pool.
* **Unexpected DHCP Activity:** DHCP traffic appears on a network segment where devices are expected to use static IP addresses.

---

<img width="1244" height="143" alt="image" src="https://github.com/user-attachments/assets/01c7269d-46f9-4125-a7a0-cbe6c7106c83" />

## SMB and NTLM Overview

### What is SMB?

**SMB (Server Message Block)** is a network protocol used to provide **file and resource sharing** between computers over a network.

SMB is commonly used in Windows environments for:

* File and folder sharing
* Accessing network shares
* Printer sharing
* Remote access to network resources

SMB commonly operates over **TCP port 445**.

### Example

```text
Client                         SMB Server
192.168.199.132                192.168.199.133
       |                              |
       | Request access to share      |
       |----------------------------->|
       |                              |
       | File / Resource Access       |
       |<-----------------------------|
```

In the analyzed traffic:

```text
192.168.199.132 → 192.168.199.133:445
```

This indicates that the client is communicating with the SMB service on the server.

---

## What is NTLM?

**NTLM (NT LAN Manager)** is a Microsoft authentication protocol used to authenticate users in Windows environments.

When a client tries to access an SMB resource, **NTLM can be used to verify the user's identity**.

NTLM uses a **challenge-response authentication mechanism**, meaning the user's password is not sent directly over the network.

### NTLM Authentication Process

```text
Client                         Server
  |                              |
  | NTLMSSP_NEGOTIATE            |
  |----------------------------->|
  |                              |
  | NTLMSSP_CHALLENGE            |
  |<-----------------------------|
  |                              |
  | NTLMSSP_AUTH                 |
  |----------------------------->|
  |                              |
  | Authentication Result        |
  |<-----------------------------|
```

### 1. NTLMSSP_NEGOTIATE

The client initiates the authentication process and indicates that it wants to use NTLM.

### 2. NTLMSSP_CHALLENGE

The server sends a **random challenge** to the client.

### 3. NTLMSSP_AUTH

The client sends an authentication response calculated using the server's challenge and password-derived information.

The user's actual password is **not sent directly**.

### 4. Authentication Result

The server verifies the authentication response.

If authentication succeeds:

```text
STATUS_SUCCESS
```

If authentication fails:

```text
STATUS_LOGON_FAILURE
```

---

## SMB vs. NTLM

The easiest way to understand the difference:

| Technology  | Purpose                                                               |
| ----------- | --------------------------------------------------------------------- |
| **SMB**     | Provides access to network resources such as files and shared folders |
| **NTLM**    | Provides authentication for the user accessing those resources        |
| **TCP 445** | Common port used by SMB                                               |

In the PCAP:

```text
SMB  → The protocol used for network resource access
NTLM → The authentication mechanism used to verify the user
```

Therefore, when we observe **SMB + NTLM + `STATUS_LOGON_FAILURE`**, it means:

> A client attempted to authenticate to an SMB server using NTLM, but the authentication attempt was rejected.

---
## Finding #6 — Failed SMB/NTLM Authentication Attempt

**Classification:** Suspicious / Requires Further Investigation

### Endpoints

| Field                   | Value             |
| ----------------------- | ----------------- |
| Client                  | `192.168.199.132` |
| SMB Server              | `192.168.199.133` |
| Service                 | SMB               |
| Port                    | `445`             |
| Authentication Protocol | NTLM              |

### Analysis

The observed traffic represents an **NTLM authentication attempt over SMB** between two distinct hosts.

The authentication process follows the standard NTLM challenge-response sequence:

```text id="u7p5kc"
Client → Server: NTLMSSP_NEGOTIATE
Server → Client: NTLMSSP_CHALLENGE
Client → Server: NTLMSSP_AUTH
Server → Client: STATUS_LOGON_FAILURE
```

### Authentication Details

1. **SMB Negotiation**
   The client and server negotiate the SMB protocol dialect. The traffic transitions from the initial SMB negotiation to **SMB2**, which is normal.

2. **NTLM Authentication Handshake**
   The client initiates NTLM authentication using `NTLMSSP_NEGOTIATE`.

3. **Server Challenge**
   The server responds with `NTLMSSP_CHALLENGE`, providing a challenge value for the authentication process.

4. **Client Authentication Response**
   The client responds with `NTLMSSP_AUTH`, containing the username:

```text
DESKTOP-2AEFM7G\user
```

and the corresponding NTLM challenge-response data.

5. **Authentication Failure**
   The server returns:

```text
STATUS_LOGON_FAILURE
```

indicating that the authentication attempt was unsuccessful.

6. **Connection Termination**
   The connection is immediately terminated with a **RST, ACK**, and no additional authentication attempts are visible in the reviewed traffic.

### Why This Is Suspicious

Unlike local LDAP traffic, this communication occurs between **two separate network hosts**:

```text
192.168.199.132 → 192.168.199.133:445
```

A failed SMB authentication attempt can have several explanations, including:

* A legitimate user entering an incorrect password.
* A misconfigured service or application.
* Brute-force or password-guessing activity.
* Password spraying.
* An attempted lateral movement operation.

However, **a single failed authentication attempt is not sufficient evidence to confirm malicious activity**.

### Indicators That Would Increase Suspicion

Further investigation would be warranted if:

* Multiple failed authentication attempts originate from `192.168.199.132`.
* Multiple usernames are targeted from the same source.
* The same source attempts authentication against multiple SMB hosts.
* The activity occurs at an unusual time or from an unexpected workstation.
* Windows Security Event **4625 (An account failed to log on)** confirms repeated failures.
* The source host is also associated with other suspicious activity in the capture.


---

<img width="1095" height="551" alt="image" src="https://github.com/user-attachments/assets/67ab9cbf-28c6-4e40-a475-a25213238b4f" />




## Finding #7 — Plaintext POP3 Credential and Email Exposure

**Classification:** Security Finding / High Risk

### Endpoints

| Field                 | Value            |
| --------------------- | ---------------- |
| Client                | `10.0.2.15`      |
| Mail Server           | `162.241.224.77` |
| Protocol              | POP3             |
| Port                  | `110`            |
| Mail Server Software  | Dovecot          |
| Authentication Method | `AUTH PLAIN`     |
| Encryption            | None observed    |


### Analysis

The observed traffic shows a complete **POP3 email retrieval session** between `10.0.2.15` and `162.241.224.77`.

The client successfully authenticated to the Dovecot mail server using:

```text id="z7r3dr"
AUTH PLAIN
```

The authentication data observed in the packet is **Base64-encoded**.

> **Important:** Base64 is an encoding mechanism, not encryption. It can be easily decoded and does not protect credentials from someone capturing the traffic.

No **STARTTLS** negotiation or encrypted POP3 session was observed before the authentication exchange.

### Authentication Result

The server responded:

```text id="5n4mkw"
+OK Logged in.
```

This confirms that the authentication was **successful**.

Therefore, the session exposed authentication material over an unencrypted POP3 connection.

### Email Retrieval

After successful authentication, the client performed several normal POP3 operations:

1. **STAT** — Checked the mailbox status.
2. **LIST** — Listed the available messages.
3. **UIDL** — Retrieved unique message identifiers.
4. **RETR 1** — Requested the first email.
5. The server then transferred approximately **56,922 octets** of email content.

The mailbox contained:

```text
3 messages
59,009 bytes total
```

The `RETR 1` operation confirms that the client retrieved the actual email content, not just message metadata.

### Security Impact

This is a significant security issue because both **authentication data and email content** can be exposed to anyone capable of monitoring the network traffic.

| Item                      | Assessment   |
| ------------------------- | ------------ |
| Protocol                  | POP3         |
| Port                      | TCP 110      |
| Authentication            | `AUTH PLAIN` |
| Encryption                | Not observed |
| Credentials exposed       | Yes          |
| Authentication successful | Yes          |
| Email content exposed     | Yes          |
| Email retrieved           | Message 1    |

### Why Base64 Is Not Encryption

The authentication data in packet 173 is Base64-encoded.

```text
Base64 ≠ Encryption
```

Base64 only converts binary/text data into a different character representation. Anyone who captures the packet can decode it without needing an encryption key.


------


<img width="1076" height="196" alt="image" src="https://github.com/user-attachments/assets/abc916e4-70a2-4a69-91a9-4f9bc0cb53fd" />


### POP3 Session Completion and Teardown

The reviewed traffic continues the same POP3 session and confirms that the client successfully retrieved **all three messages** from the mailbox.

### Analysis

The client retrieved the three messages sequentially:

| Message   | POP3 Command |            Size |
| --------- | ------------ | --------------: |
| Message 1 | `RETR 1`     | `56,922` octets |
| Message 2 | `RETR 2`     |  `1,034` octets |
| Message 3 | `RETR 3`     |  `1,053` octets |

After downloading all three messages, the client sent:

```text id="8b1y2v"
QUIT
```

The server responded:

```text id="fl9lpm"
+OK Logging out.
```

The TCP connection was then closed normally using a **FIN/ACK exchange**, indicating a clean session termination.

### Final Assessment

This traffic confirms that the POP3 session was a **complete and successful email retrieval session**, rather than a partial or interrupted transfer.

The complete session demonstrates:

1. Successful authentication using **`AUTH PLAIN`**.
2. Authentication data transmitted without an observed TLS-protected session.
3. Retrieval of **all three messages**.
4. Successful transfer of the complete email contents.
5. Normal logout using `QUIT`.
6. Clean TCP connection termination.

-----




<img width="1190" height="357" alt="image" src="https://github.com/user-attachments/assets/bc4c18b2-5f1a-4411-a01a-431067b19fdb" />


<img width="1130" height="161" alt="image" src="https://github.com/user-attachments/assets/0e59bebf-0574-4403-addf-b62fbd527da6" />







## Finding #8 — Anonymous FTP Access and Directory Enumeration

**Classification:** Suspicious / Requires Investigation

### Endpoints

| Field            | Value                                  |
| ---------------- | -------------------------------------- |
| Client           | `192.168.56.102`                       |
| FTP Server       | `192.168.56.101`                       |
| Service          | FTP                                    |
| Port             | TCP 21                                 |
| FTP Server       | `vsFTPd 2.3.4`                         |
| Authentication   | Anonymous FTP                          |
| Access Confirmed | Successful login and directory listing |

---

### Session Overview

The observed traffic shows an FTP session from `192.168.56.102` to `192.168.56.101`.

The activity progressed from FTP service identification and anonymous authentication to successful directory enumeration.


---

## Analysis

### 1. Successful Anonymous FTP Login

The client authenticated using the standard anonymous FTP sequence:

```text id="d3q0wl"
USER anonymous
PASS password
```

The server responded:

```text id="j8z3xu"
230 Login successful.
```

This confirms that the FTP server permits **anonymous authentication**.

Anonymous FTP can be legitimate in some environments, but it should be explicitly authorized and appropriately restricted. If unauthorized, it can allow users to access files without providing valid credentials.

---

### 2. FTP Server Version

The server banner identifies the software as:

```text id="t7x1mc"
vsFTPd 2.3.4
```

This version is security-sensitive because a **trojanized/backdoored distribution of vsFTPd 2.3.4** was historically distributed and associated with **CVE-2011-2523**.

---

### 3. Directory Enumeration

The FTP session subsequently used a separate FTP **data connection** to transfer directory information.

The server returned:

```text id="q8j1h4"
226 Directory send OK.
```

This response confirms that a **directory listing was successfully transferred**.

FTP normally uses:

* **Control connection:** TCP port 21 for commands and responses.
* **Data connection:** A separate connection for directory listings and file transfers.

Therefore, the activity progressed beyond authentication and successfully obtained information about the server's directory structure.

### Important Distinction

The capture confirms:

```text
Anonymous Login
        ↓
Successful Authentication
        ↓
Directory Listing
        ↓
Session Termination
```

However, there is **no evidence in the reviewed traffic of an actual file download using `RETR`**.

Therefore, the capture confirms **directory enumeration**, but does not confirm file exfiltration.

---

## Correlation with Finding #1

The source IP `192.168.56.102` was previously identified performing a **TCP port scan** against `192.168.56.101`.

The subsequent FTP activity provides a useful correlation:

```text
Port Scan
    ↓
FTP Service Identified
    ↓
Anonymous FTP Login
    ↓
Directory Enumeration
    ↓
Session Termination
```

This sequence is consistent with a **reconnaissance → service access → enumeration** pattern.

Because the same source and destination are involved, these events should be investigated as part of the same activity rather than treated as completely unrelated events.

---

<img width="1244" height="315" alt="image" src="https://github.com/user-attachments/assets/28b107d7-5fe4-47de-a792-2f6e85f03192" />


## Finding #9 — Telnet Interactive Session

**Classification:** Suspicious / Requires Further Investigation

### Endpoints

| Field              | Value                                              |
| ------------------ | -------------------------------------------------- |
| Client             | `192.168.56.102`                                   |
| Telnet Server      | `192.168.56.101`                                   |
| Protocol           | Telnet                                             |
| Port               | TCP 23                                             |
| Source Correlation | Same source as previous port scan and FTP activity |


### Analysis

The traffic shows a **Telnet connection** established from `192.168.56.102` to `192.168.56.101` over TCP port `23`.

The initial packets contain standard Telnet option negotiation, including:

* Terminal Type
* Terminal Speed
* Window Size
* Echo
* Flow Control
* X Display Location

These negotiations are normal and are required to establish the characteristics of an interactive Telnet terminal.

### Interactive Session Evidence

Packet `357` contains approximately **620 bytes** of server-to-client data. Based on its position immediately after the Telnet negotiation, this is consistent with a **login banner, system message, or login prompt**.

Starting from packet `359`, the traffic changes to repeated **small 1-byte exchanges** between the client and server.

This pattern is characteristic of an **interactive Telnet terminal**, where keystrokes can be transmitted individually rather than being buffered into larger application-layer messages.

```text id="0f0g8m"
Server → Client: Login banner / prompt
       ↓
Client ↔ Server: Interactive character exchange
```

### Correlation With Previous Activity

This activity is particularly significant because the source IP is the same:

```text id="zq8a6u"
192.168.56.102
```

The same host was previously observed:

```text
Port Scan
     ↓
FTP Connection
     ↓
Anonymous FTP Login
     ↓
FTP Directory Enumeration
     ↓
Telnet Connection
```
-----


<img width="1235" height="410" alt="image" src="https://github.com/user-attachments/assets/1741e0fd-1caf-4670-a4e0-edd9180a1881" />


## Finding #10 — SMTP Mail Submission / Connectivity Test

**Classification:** Benign / Expected Traffic

### Endpoints

| Field           | Value                |
| --------------- | -------------------- |
| Client          | `192.168.110.9`      |
| SMTP Server     | `80.154.108.237`     |
| Server Hostname | `mail.webertest.net` |
| Protocol        | SMTP                 |
| Port            | TCP 25               |


### Analysis

The observed traffic follows the standard **SMTP mail submission sequence**:

```text id="9d1qpm"
HELO
  ↓
MAIL FROM
  ↓
RCPT TO
  ↓
DATA
  ↓
Message Accepted
  ↓
QUIT
```

The SMTP server successfully accepted the message and returned:

```text id="6c2s8h"
250 ok: Message 8725 accepted
```

The session then terminated normally using `QUIT`, followed by a clean TCP connection teardown.

### Notable Observations

#### 1. Null Sender

The client used:

```text id="1l8j8r"
MAIL FROM: <>
```

An empty sender address is valid SMTP syntax and is commonly used for **bounce or delivery-status notifications**. It can also appear in automated testing and monitoring traffic.

By itself, this does not indicate malicious activity.

#### 2. Synthetic Test Message

The message subject was:

```text id="a5i9gq"
SMTP Ping
```

The body contained a repetitive test pattern:

```text id="z2v4hh"
AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ...
```

The combination of a test-oriented subject and repetitive payload strongly suggests that this was a **synthetic SMTP connectivity or mail-server health test**, rather than a normal user-generated email.

#### 3. Successful Delivery

The SMTP server accepted the message successfully:

```text id="1e7w4c"
250 ok: Message 8725 accepted
```

This confirms that the SMTP transaction completed successfully.

### Conclusion

The traffic represents a **normal and successful SMTP transaction**, most likely generated as an automated mail-server connectivity or health check.

There are no clear indicators of:

* Spam activity
* Malware delivery
* Suspicious attachments
* Authentication bypass
* SMTP command abuse
* Exploitation attempts

**Final Classification: Benign / Expected Traffic**
-------




<img width="1027" height="277" alt="image" src="https://github.com/user-attachments/assets/6e50d42d-4060-49df-a3d6-bf8642c9be91" />
<img width="1025" height="285" alt="image" src="https://github.com/user-attachments/assets/47b15534-00b7-4920-b166-35f4790c9a7b" />


# Finding #11 — Large-Scale TCP Port Scan

**Classification:** Reconnaissance — TCP Port Scanning

## Endpoints

| Field                | Value            |
| -------------------- | ---------------- |
| Source (Scanner)     | `192.168.56.102` |
| Destination (Target) | `192.168.56.101` |
| Source Port          | `46729`          |
| Protocol             | TCP              |
| Scan Type            | TCP SYN Scan     |

## Evidence

The capture shows `192.168.56.102` sending a large number of TCP SYN packets to different ports on `192.168.56.101`.

The same source port (`46729`) is used throughout the scan.

The observed pattern is:

```text
192.168.56.102 → 192.168.56.101    SYN
192.168.56.101 → 192.168.56.102    SYN-ACK / RST-ACK
192.168.56.102 → 192.168.56.101    RST
```

* **SYN-ACK** indicates that the destination port is open.
* **RST-ACK** indicates that the destination port is closed.
* After receiving a response, the scanner moves to the next port.

## Extended Scan Activity

The scan continues into packet numbers **1000+**, while an earlier part of the same scan was observed around packets **470–510**.

Ports observed in this segment include:

```text
10628, 13722, 17988, 8200, 32768,
9111, 31038, 27356, 34572, 1066,
513, 32783
```

The large number of probes and very short intervals between them indicate an **automated and sustained port scan**, rather than a manual connection attempt.

## Open Ports Identified

The following ports were confirmed as open based on observed `SYN-ACK` responses:

|   Port | Associated Service      |
| -----: | ----------------------- |
|   `22` | SSH                     |
|   `23` | Telnet                  |
|   `80` | HTTP                    |
|  `111` | RPCbind                 |
|  `135` | MS RPC                  |
|  `139` | NetBIOS Session Service |
|  `445` | SMB                     |
|  `513` | rlogin                  |
| `5900` | VNC                     |

> **Note:** An open port only confirms that the service was reachable. It does not, by itself, prove successful authentication or exploitation.

## Notable Observation — Port 513

Port `513` is associated with **rlogin**.

The scanner received a `SYN-ACK` from port `513`, confirming that the port was open and reachable during the capture.

This is significant because rlogin is an older remote-access protocol that is generally considered insecure and should be avoided in modern environments.
-----

<img width="1182" height="442" alt="image" src="https://github.com/user-attachments/assets/95e180f4-7035-4306-ac8d-64c64bf3e4f6" />


## Finding #12 — Service Enumeration and Metasploitable2 Identification

**Classification:** Expected Penetration Testing / Lab Activity

### Endpoints

| Field                  | Value                        |
| ---------------------- | ---------------------------- |
| Scanner / Testing Host | `192.168.56.102`             |
| Target                 | `192.168.56.101`             |
| Target Hostname        | `metasploitable.localdomain` |
| Environment            | Metasploitable2 Lab          |

### Evidence

The same source host previously observed performing the TCP port scan continued with **service enumeration and banner grabbing** against the target.

```text
1096: SSH
      Server: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1

1103: RSH
      Server → Client data

1108: SMTP
      220 metasploitable.localdomain ESMTP Postfix (Ubuntu)

1113: FTP
      220 (vsFTPd 2.3.4)

1116: FTP
      500 OOPS:

1118: FTP
      vsf_sysutil_recv_peek: no data

1122: HTTP
      GET / HTTP/1.0
```

### Metasploitable2 Identification

The SMTP banner contains:

```text
metasploitable.localdomain
```

This hostname is associated with the **Metasploitable2 intentionally vulnerable training VM**.

The observed services also strongly support this identification, including:

* `vsFTPd 2.3.4`
* OpenSSH
* RSH
* SMTP/Postfix
* HTTP
* Telnet
* SMB

These are consistent with the deliberately exposed services found on Metasploitable2.

### Banner Grabbing

The activity demonstrates **service enumeration / banner grabbing**.

The testing host is collecting information about the services running on the target, including:

```text
Service → Version / Software Information
```

For example:

```text
SSH  → OpenSSH_4.7p1
FTP  → vsFTPd 2.3.4
SMTP → Postfix (Ubuntu)
```

This information can help a penetration tester identify potential vulnerabilities and determine which services should be investigated further.

### FTP Error Observation

The FTP service also returned:

```text
500 OOPS:
vsf_sysutil_recv_peek: no data
```

This indicates that the FTP server encountered an error while processing the interaction.

The error is consistent with malformed-input or vulnerability-testing activity, but **the packet capture alone should not be used to claim that the vsFTPd backdoor was successfully exploited**.

No successful shell or post-exploitation activity is established by these packets alone.

### Correlation With Previous Findings

The identification of the target as a Metasploitable2 lab system provides important context for the previous observations:

```text
TCP Port Scan
      ↓
Service Enumeration
      ↓
Anonymous FTP Login
      ↓
FTP Directory Enumeration
      ↓
Telnet / RSH Activity
      ↓
SMB Authentication Testing
```

These activities are consistent with a **penetration-testing workflow** against an intentionally vulnerable training machine.

### Revised Overall Assessment

The earlier findings should therefore be interpreted within the context of the lab environment.

| Activity                | Previous Interpretation     | Revised Context                                   |
| ----------------------- | --------------------------- | ------------------------------------------------- |
| TCP Port Scan           | Suspicious reconnaissance   | Expected pentest reconnaissance                   |
| FTP Anonymous Login     | Suspicious access           | Expected testing of an exposed service            |
| FTP Directory Listing   | Suspicious enumeration      | Expected service enumeration                      |
| Telnet Session          | Suspicious                  | Expected testing of exposed remote-access service |
| SMB/NTLM Failure        | Potential credential attack | Likely authentication testing                     |
| Service Banner Grabbing | Suspicious reconnaissance   | Expected vulnerability identification             |

------

