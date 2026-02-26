# 🛡️ TRAFFIX: Real-Time Network Security & Traffic Monitor

**Traffix** is a distributed network monitoring system designed to provide deep visibility into endpoint traffic. It consists of a lightweight Python-based **Agent** that captures live packets and a centralized **Manager** (FastAPI) that processes, alerts, and visualizes the data in a modern, interactive dashboard.



---

## 🚀 Key Features

### 1. **Live Traffic Streaming**
* **Real-time Visualization:** Packets are captured and broadcasted instantly to the dashboard via WebSockets.
* **Process Identification:** Automatically maps network traffic to the specific software (e.g., Chrome, Slack, Discord) and Process ID (PID) generating it.

### 2. **Security & Threat Detection**
* **Port Scan Detection:** Heuristic engine that identifies and alerts when an endpoint is being scanned (Sequential port access detection).
* **Blacklist Monitoring:** Dynamic IP blacklisting. Alerts are triggered immediately if an agent attempts to communicate with a malicious IP.
* **Live Alerts:** High-visibility pulsing UI banners for critical security events.

### 3. **Geographical Intelligence**
* **Global Map Pings:** Interactive Leaflet.js map showing real-time geographical destinations of outgoing traffic using dark-mode aesthetics.
* **Country Distribution:** Statistical breakdown of traffic by country to identify suspicious data exfiltration.

### 4. **Advanced Analytics & Forensic Tools**
* **Timeframe Filtering:** Investigate incidents using granular time filters (from the last 15 minutes to the past year) powered by SQL indexing.
* **Bandwidth Analysis:** Identify "Data Hogs" with MegaByte (MB) usage tracking per application.
* **Top Processes Table:** Detailed forensic table ranking the most active processes on the network with visual activity bars.

---

## 🏗️ Architecture



* **Agent (Python):** Uses `Scapy` for packet sniffing and `psutil` for process mapping. Sends data via UDP to minimize system overhead.
* **Manager (FastAPI):** High-performance asynchronous backend with a lifespan-managed event loop for real-time broadcasting.
* **Database (PostgreSQL):** Optimized with SQL Indexes on `timestamp` and `agent_id` for lightning-fast historical queries.
* **Frontend (JS/Chart.js/Leaflet):** Modern Dark-Mode UI designed for SOC (Security Operations Center) environments.

---

## 🛠️ Installation & Setup

### Prerequisites
* **Python 3.12+**
* **PostgreSQL**
* **Npcap** (Required for Windows users to enable Scapy packet sniffing)

### 1. Clone the Repository
```bash
git clone [https://github.com/your-username/traffix.git](https://github.com/your-username/traffix.git)
cd traffix
