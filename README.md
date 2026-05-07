# 🦅 ShadowHarvest-CPP

**ShadowHarvest** is a high-performance security research tool written in C++. It focuses on Windows environment telemetry, post-exploitation techniques, and credential analysis. This project demonstrates advanced knowledge of Windows Internals, Cryptography, and Modern C++ patterns.

## ⚠️ Disclaimer
This tool is for **educational and authorized security testing purposes only**. The author is not responsible for any misuse or damage caused by this program. Usage for attacking targets without prior mutual consent is illegal.

## 🚀 Technical Features

### 1. Windows Internals & Evasion
*   **Anti-Debugging:** Implements manual checks of the **Process Environment Block (PEB)** (`BeingDebugged` flag and `NtGlobalFlag`) to detect and halt execution in analysis environments.
*   **Dynamic API Resolving:** Uses `GetProcAddress` and `GetModuleHandle` to resolve critical WinAPI functions at runtime, evading Static Analysis and **Import Address Table (IAT)** hooks.
*   **String Obfuscation:** All sensitive strings (paths, database names) are encrypted using a custom **XOR-based algorithm** to bypass string-based detection.

### 2. Credential Extraction
*   **Chromium-based Browser Analysis:** Supports Chrome, Edge, Brave, and Opera.
*   **OS Cryptography:** Utilizes the Windows **BCrypt API** to implement manual **AES-256-GCM** decryption.
*   **Data Parsing:** Uses the `sqlite3` library to parse and extract data from `Login Data` databases.
*   **Session Hijacking:** Automated harvesting of Discord tokens and Telegram `tdata` session folders.

### 3. Networking & Exfiltration
*   **Asynchronous ARP Scanner:** Integrated multithreaded network discovery using `std::async` to identify active hosts in the local subnet via ARP requests.
*   **Custom Exfiltration:** Implements a native **WinHTTP-based** engine to send gathered telemetry to a remote Telegram Bot via `multipart/form-data`. No external heavy libraries like `libcurl` are required.

## 🏗️ Architecture
The project follows **SOLID** principles and uses **Modern C++ (C++17)**:
*   `SystemRecon`: Gathers host telemetry (OS version, PC name, user).
*   `BrowserStealer`: Handles database cloning, master key extraction (DPAPI), and decryption.
*   `DiscordStealer`: Parses LevelDB storage and extracts tokens using Regex.
*   `Exfiltration`: Manages secure data delivery to the C2 (Telegram).
*   `GhostHunter`: Handles environment safety and anti-debug logic.

## 🛠️ Requirements
*   Windows 10/11
*   Visual Studio 2022
*   C++17 Standard
*   Libraries: `bcrypt.lib`, `crypt32.lib`, `winhttp.lib`, `iphlpapi.lib`.
