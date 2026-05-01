# NetWatch v1.0 ◈ Network Traffic Monitor

NetWatch is a high-performance, real-time network packet sniffer and traffic analysis platform. It combines a robust **C++ packet-capture engine** with a modern **web-based dashboard** to provide live insights into network activity.



## 🚀 Features
- **Real-time Sniffing:** Live packet capture using the Npcap/libpcap driver.
- **Protocol Decoding:** Deep packet inspection for Ethernet, IPv4, TCP, UDP, and ICMP.
- **Service Mapping:** Automatically identifies applications (HTTP, HTTPS, DNS, SSH, etc.) based on port numbers.
- **Live Statistics:** Real-time counters for total packets, protocol distribution, and average packet size.
- **Interactive UI:** Cyber-themed dashboard with Start/Stop controls and a system log console.
- **Advanced Filtering:** Instant filtering by Protocol, Source IP, Destination IP, or Service.

## 🛠️ Tech Stack
- **Backend:** C++17, Winsock2 (Networking), Npcap SDK (Packet Sniffing).
- **Frontend:** HTML5, CSS3 (Custom Cyber-theme), Vanilla JavaScript (ES6).
- **API:** Custom lightweight HTTP REST API (running on port 8080).

## 📋 Prerequisites
1. **Windows OS** (10 or 11).
2. **Npcap:** [Download and install Npcap](https://npcap.com/dist/npcap-1.79.exe). 
   *   **Important:** During installation, check the box: *"Install Npcap in WinPcap API-compatible Mode"*.
3. **Compiler:** MinGW-w64 (g++) or any C++17 compatible compiler.

## 🔨 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/NetWatch.git](https://github.com/your-username/NetWatch.git)
   cd NetWatch

2. **Using cmd , go to git repo and compile using:**
    g++ server.cpp -o server.exe -I"C:/npcap-sdk-1.16/Include" -L"C:/npcap-sdk-1.16/Lib/x64" -lwpcap -lPacket -lws2_32 -ladvapi32 -lpthread -std=c++17 -O2

3. **Right Click on server.exe:**
4. **Open index.html in any modern browser:**


🖥️ Usage
1. **Open the dashboard and ensure the status says IDLE**
2. **Select your active Network Interface (Wi-Fi or Ethernet) from the dropdown**
3. **Click ▶ START to begin capturing**
4. **Use the Filters section to narrow down specific traffic (e.g., type "8.8.8.8" in Destination IP)**


---

## 💻 Complete Project Code

### 1. `server.cpp` (The C++ Backend)
This handles the raw packet sniffing and hosts the local API

### 2. `index.html` (The UI Structure)
This provides the dashboard layout

### 3. `style.css` (The Visual Design)
This creates the "Cyber-themed" dark mode look

### 4. `app.js` (The Frontend Logic)
This handles the API polling and UI updates

---
