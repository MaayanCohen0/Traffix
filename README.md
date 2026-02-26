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

### 2. Install Dependencies
Install the required Python libraries for both the Manager (Server) and the Agent (Collector).

**For the Manager:**
```bash
cd manager
pip install -r requirements_manager.txt



**For the Agent::**
```bash
cd agent
pip install -r requirements_agent.txt

###3. Create the Database (Required)
Before running the application, you must manually create the database in PostgreSQL. You can do this via pgAdmin or the psql command line
```bash
-- Run this command in your PostgreSQL Query Tool
CREATE DATABASE traffix_db;

###4. Configure & Initialize
Update the DATABASE_URL in manager/database.py with your PostgreSQL credentials:
```bash
# Replace 'username' and 'password' with your real PostgreSQL credentials
DATABASE_URL = "postgresql://username:password@localhost:5432/traffix_db"

## 🚦 How to Run
###Step 1: Start the Manager
The manager handles the API, database storage, and the real-time Dashboard.

```bash
cd manager
python manager.py

###Step 2: Start the Agent
The agent must be run with Administrative/Root privileges to sniff network traffic.

####On Windows (Run CMD/PowerShell as Admin):

```bash
cd agent
python agent.py

####On Linux/macOS:

```bash
cd agent
sudo python3 agent.py

###Step 3: Access the Dashboard
Once both are running, open your web browser and navigate to:
http://localhost:8000/dashboard/index.html (or open the index.html file directly).

## ⚙️ Dynamic Configuration (config.json)
The system supports Hot-Reloading—updates to this file are applied instantly without restarting the server:

agent_names: Map IP addresses to workers names.

blacklist_ips: List of restricted IPs that trigger immediate security alerts.

server: Host and port configuration for the UDP listener.

## 🖥️ UI & Administrative Controls
Interactive Filtering: Filter all charts and tables by specific Agent or custom Time Range (e.g., Last 15m, 24h, 1y).

Reset Database: A built-in administrative button to wipe and rebuild the database schema. Includes a safety confirmation dialog to prevent accidental data loss.

Professional UI: Rounded "capsule" filter box, responsive grid layout, and custom-designed scrollbars.
