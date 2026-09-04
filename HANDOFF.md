# Project Handoff: Bourass FastDNS (Android Client)

**Document Version:** 1.0  
**Generated Date:** September 4, 2026  
**Repository:** [github.com/ilyassbourass/bourass-fastdns-android](https://github.com/ilyassbourass/bourass-fastdns-android)  
**Local Workspace:** `C:\Users\PC\Documents\Default Project\bourass-fastdns-android`  
**Target Hardware:** Xiaomi Redmi Phone (`ADB Serial: WOZ5BUMFVGZTY5WO`, Rooted via Magisk/SU)

---

## 1. Executive Summary

The objective of this project is the design, implementation, and deployment of a standalone, lightweight Android VPN client (**Bourass FastDNS**) written natively in Kotlin. The application implements a DNS-over-TCP tunneling protocol, capturing system-wide IPv4 traffic using Android's native `VpnService` (`tun0`) and encapsulating IP packets inside DNS `NULL` (QTYPE 10) queries and responses.

Unlike commercial third-party wrappers, this solution is:
- **Lightweight:** 5.7 MB APK size (compared to 66+ MB Flutter/Go implementations).
- **Native:** Implemented in pure Kotlin using Android platform APIs (`VpnService`, `Cipher`, `Socket`).
- **Unconstrained:** No client-side session timeout timers or third-party ad SDK dependencies.

---

## 2. System Architecture & Components

```
+-------------------------------------------------------------+
|                      Android System                         |
|  (Chrome, YouTube, Apps generate standard IPv4 packets)     |
+------------------------------+------------------------------+
                               |
                               v
                     [ tun0 (VpnService) ]
                               |
                               | (Raw IPv4 Datagrams)
                               v
+-------------------------------------------------------------+
|                 FastDnsVpnService (Kotlin)                  |
|  - Manages TUN lifecycle, routing, and MTU (1400)           |
|  - Protects engine sockets via protect(Socket)              |
|  - Dispatches uplink packets to FastDnsEngine               |
|  - Writes downlink packets received from engine to tun0     |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                   FastDnsEngine (Kotlin)                    |
|  - Dual TCP Sockets: Data Socket & Polling Socket           |
|  - DNS Wire Formatting: 2-byte length prefix + RFC header   |
|  - Uplink: Encrypts, Base32 encodes, chunks into labels     |
|  - Downlink: Continuous polling loop for incoming packets   |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                   FastDnsCrypto (Kotlin)                    |
|  - KDF: HMAC-SHA256 key derivation hierarchy               |
|  - Encryption: AES-GCM (12-byte Nonce, 128-bit Tag)         |
|  - Framing: Base32 label chunking (RFC 4648 compliant)      |
+-------------------------------------------------------------+
```

---

## 3. Detailed Component Breakdown

### 3.1. `MainActivity.kt`
- **Path:** `app/src/main/java/com/bourass/fastdns/MainActivity.kt`
- **Responsibilities:**
  - UI management (status display, server display, real-time throughput metrics).
  - Handles the Android VPN preparation flow via `VpnService.prepare(this)`.
  - Sends explicit intents (`ACTION_CONNECT`, `ACTION_DISCONNECT`) to `FastDnsVpnService`.
  - Subscribes to the live service callback to update connection status.

### 3.2. `FastDnsVpnService.kt`
- **Path:** `app/src/main/java/com/bourass/fastdns/FastDnsVpnService.kt`
- **Responsibilities:**
  - Operates as a Foreground Service with an ongoing system notification displaying real-time speed indicators (`↑ KB/s ↓ KB/s`).
  - Creates and configures the virtual network interface `tun0`:
    - Assigned Address: `10.8.0.2 / 24`
    - Global Route: `0.0.0.0/0` (all IPv4 traffic captured)
    - DNS Servers: `8.8.8.8`, `8.8.4.4`
    - MTU: 1400 bytes
    - Disallowed Application: Excludes `com.bourass.fastdns` package to prevent routing loops.
  - Sockets Protection: Invokes `protect(socket)` on underlying TCP sockets so tunnel traffic bypasses the VPN interface.
  - Uplink Loop: A background thread reads raw IP packets from `tun0` and feeds them to `FastDnsEngine.sendUplink()`.
  - Downlink Loop: Registers a listener on the engine; incoming decrypted IP packets are directly written back to `tun0` via `FileOutputStream`.

### 3.3. `FastDnsEngine.kt`
- **Path:** `app/src/main/java/com/bourass/fastdns/FastDnsEngine.kt`
- **Responsibilities:**
  - **Connection Management:** Establishes dual TCP connections on port 53 to carrier resolvers (`105.73.34.105:53`, `105.73.34.106:53`) with fallback to authoritative server (`213.160.77.162:53`).
  - **Uplink Segmentation:** Splits large IP packets into maximum 80-byte slices before encryption to guarantee total DNS query name length does not exceed RFC 1035 limits (253 bytes).
  - **Downlink Polling:** Manages a polling loop issuing queries with the format:
    `0-poll.<shortSession>.0.<rand>.s<ip_octets>.<zone>`
  - **DNS Wire Serializer:**
    - Prefixes all messages with a 2-byte Big-Endian length header (DNS-over-TCP standard).
    - Formats standard 12-byte DNS headers with `QDCOUNT=1`, `ANCOUNT=0`, `NSCOUNT=0`, `ARCOUNT=0`.
    - Encodes domain labels using length-prefixed octets ending in a null byte (`0x00`).
    - Appends `QTYPE=10` (`NULL`) and `QCLASS=1` (`IN`).
  - **DNS Wire Deserializer:** Reads response frames, parses the answer section, locates matching resource records, and extracts `RDATA` bytes.

### 3.4. `FastDnsCrypto.kt`
- **Path:** `app/src/main/java/com/bourass/fastdns/FastDnsCrypto.kt`
- **Cryptographic Specifications:**
  - **Master Key:** `3529de18502ac35a534ce8b541d834228ca3c1cd89b6ce3d31cf44072f0e477a`
  - **Default Sub ID:** `4db6aa8190671ed0`
  - **Default Install ID:** `73f7f016233cf06ab0eeeea89e0ec50c`
  - **Certificate Hex:** `c39a8841ecb915f1ba6462f486ee009219b052db290f5209f53d34c31c56ab41`
  - **SubKey Derivation:** `HMAC-SHA256(MasterKey, SubId)`
  - **SessionKey Derivation:** `HMAC-SHA256(SubKey, InstallId || 0x00 || SessionHex || 0x00 || CertHex)`
  - **Cipher:** `AES/GCM/NoPadding` with 12-byte random IV and 128-bit authentication tag.
  - **Encoding:** RFC 4648 Base32 alphabet (`abcdefghijklmnopqrstuvwxyz234567`), lowercase, without padding characters.

---

## 4. CI/CD & Build Pipeline

The project uses GitHub Actions for remote compilation because the local host environment does not maintain an Android SDK / Gradle installation.

- **Workflow File:** `.github/workflows/build.yml`
- **Runner Environment:** `ubuntu-latest`, JDK 17 (Eclipse Temurin), Android SDK Platform 34, Build Tools 34.0.0.
- **Build Configurations:**
  - Android Gradle Plugin (AGP): `8.7.3`
  - Kotlin Plugin: `1.9.24`
  - Gradle Wrapper: `8.9`
  - Compile SDK: `34`, Min SDK: `24`, Target SDK: `34`

### Build History & Resolutions

| Run ID | Commit Message | Result | Resolution / Notes |
| :--- | :--- | :--- | :--- |
| `33907303608` | *Initial Bourass FastDNS Android app* | **Failed** | Gradle 9.7.1 incompatible with older AGP. Migrated to modern plugin DSL and fixed version compatibility. |
| `33907598219` | *Fix Gradle config: use AGP 8.7.3, Gradle 8.9* | **Failed** | AAPT error: missing launcher icons (`ic_launcher`, `ic_launcher_round`). Generated adaptive vector drawables and fallback PNGs. |
| `33907964180` | *Add launcher icons (adaptive + PNG fallback)* | **Success** | Produced `app-debug.apk` (5.7 MB). Successfully installed on device. |
| `33908788954` | *Fix FastDNS QNAME wire format* | **Success** | Adjusted label prefixes and poll name construction to match wire captures. |
| `33909366087` | *Replace bulky handshake with poll verification and add 80-byte uplink chunking* | **Success** | Chunked uplink packets to stay strictly within the RFC 1035 253-byte limit. |

---

## 5. Network Protocol Findings & Diagnostic Logs

During live device testing on the connected hardware via ADB, the following protocol details and behaviors were recorded:

### 5.1. Wire Format Validation
- **Label Structure:** The first label of an uplink frame must include the `0-` prefix directly attached to the first Base32 chunk (e.g., `0-<base32_slice>`), not as an independent dot-delimited label (`0.<base32_slice>`).
- **RFC 1035 Size Constraint:** A full DNS query name cannot exceed 253 bytes. Early prototypes generated query strings of 284 bytes which were dropped by upstream resolvers without response. Uplink chunking was constrained to 80 raw bytes (producing ~128 Base32 chars, resulting in ~210-230 byte domain names).

### 5.2. Resolver Interactivity
- **TCP Reachability:** Sockets connecting to `105.73.34.105:53` and `105.73.34.106:53` establish TCP three-way handshakes immediately on carrier data networks.
- **Reset Behavior Observed:** In test runs with synthetic poll queries (`0-poll.60287.0.33807.s10.8.0.2.dns3.marocdns.uk`), the resolver closed the TCP stream with `java.net.SocketException: Connection reset` shortly after receiving the first frame.
- **Reference Capture Contrast:** Analysis of `faiz_tun6.pcap` demonstrated that active sessions maintained 47,175 TCP/53 packets with persistent TCP sessions and specific answer lengths, indicating the server expects session initialization parameters aligned with active session tables in memory.

---

## 6. Project File Tree

```
C:\Users\PC\Documents\Default Project\bourass-fastdns-android\
├── .git\
├── .github\
│   └── workflows\
│       └── build.yml
├── app\
│   ├── build.gradle
│   └── src\
│       └── main\
│           ├── AndroidManifest.xml
│           ├── java\com\bourass\fastdns\
│           │   ├── FastDnsCrypto.kt
│           │   ├── FastDnsEngine.kt
│           │   ├── FastDnsVpnService.kt
│           │   └── MainActivity.kt
│           └── res\
│               ├── drawable\
│               │   ├── ic_launcher_background.xml
│               │   └── ic_launcher_foreground.xml
│               ├── layout\
│               │   └── activity_main.xml
│               ├── mipmap-anydpi-v26\
│               │   ├── ic_launcher.xml
│               │   └── ic_launcher_round.xml
│               ├── mipmap-hdpi\ ...
│               ├── mipmap-mdpi\ ...
│               ├── mipmap-xhdpi\ ...
│               ├── mipmap-xxhdpi\ ...
│               ├── mipmap-xxxhdpi\ ...
│               └── values\
│                   └── strings.xml
├── build.gradle
├── gradle\
│   └── wrapper\
│       └── gradle-wrapper.properties
├── gradle.properties
├── settings.gradle
└── dist_v3\
    └── BourassFastDNS-debug\
        └── app-debug.apk
```

---

## 7. Next Steps & Recommendations

1. **Session Lifecycle Alignment:**
   - Investigate the specific handshake sequence required to avoid TCP resets upon initial session registration.
   - Cross-reference the exact bootstrap sequence from decompiled source (`TcpInjectorVpnService` / `NativeMethods`) to determine if an auxiliary HTTP API call is required prior to DNS socket establishment.

2. **Socket Keep-Alive & TCP Framing:**
   - Review TCP socket options (`SO_KEEPALIVE`, `TCP_NODELAY`) to match native engine characteristics.
   - Ensure DNS transaction IDs in response parsing match outgoing transaction IDs across multiple concurrent multiplexed queries.

3. **Deployment Workflow:**
   - To build and test future iterations:
     1. Push changes to `main` branch on GitHub.
     2. Wait for GitHub Actions build to complete (`gh run list`).
     3. Download artifact: `gh run download <RUN_ID> -D dist`.
     4. Install on device: `adb -s WOZ5BUMFVGZTY5WO push dist/.../app-debug.apk /data/local/tmp/app.apk && adb -s WOZ5BUMFVGZTY5WO shell "su -c 'pm install -r /data/local/tmp/app.apk'"`.
