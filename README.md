# 🛡️ TRAFFIX: Real-Time Network Security & Traffic Monitor

**Traffix** is a high-performance, distributed network monitoring system designed for deep visibility into endpoint traffic. It features a lightweight Python-based **Agent** for packet sniffing and a centralized **FastAPI Manager** for real-time analysis, security alerting, and interactive visualization.



---

## 🚀 Key Features

### 1. **Live Traffic Analysis**
**Real-time Streaming:** Packets are captured and broadcasted instantly to the dashboard via WebSockets.
**Process Mapping:** Automatically identifies which local software (e.g., Chrome, Discord) is generating specific network traffic using `psutil`.

### 2. **Advanced Security Detection**
**Port Scan Identification:** Heuristic engine that detects sequential port access patterns to identify scanning attempts.
**Dynamic Blacklisting:** Real-time alerts when an internal agent communicates with known malicious IPs defined in `config.json`.
**Security Banners:** Instant visual alerts on the dashboard for critical security events.

### 3. **Geographical & Forensic Intelligence**
**Interactive Map:** Live Leaflet.js map showing geographical destinations of outgoing traffic using dark-mode aesthetics.
**Granular Filtering:** Investigate incidents using time-based filters (15m to 1y) powered by optimized PostgreSQL indexing.
**Bandwidth Monitoring:** Visual breakdown of data consumption (MB) per application.

---

## 🏗️ Architecture & Tech Stack



**Backend:** FastAPI (Python 3.12) with asynchronous WebSocket broadcasting.
**Agent:** Scapy for low-level packet sniffing and multi-threading for non-blocking processing.
**Database:** PostgreSQL with SQLAlchemy ORM. Optimized with **thread-locks** to prevent race conditions during DB resets.
**Frontend:** Modern Dark-Mode UI using Chart.js, Leaflet.js, and Vanilla JavaScript.


## 🛠️ Installation & Setup

### Prerequisites
**Python 3.12+** 
**PostgreSQL Server** 
**Npcap** (Required for Windows users to enable Scapy sniffing) 

### 1. Clone the Repository
```bash
git clone https://github.com/MaayanCohen0/traffix.git
cd traffix
```
### 2. Environment Configuration
Create a .env file in the manager/ directory based on .env.example:
```bash
DATABASE_URL=postgresql://user:password@localhost:5432/traffix_db
```

Create a .env file in the agent/ directory based on .env.example:
```bash
MANAGER_IP=127.0.0.1
MANAGER_PORT=2053
```
### 3. Install Dependencies
Install the required Python libraries for both the Manager (Server) and the Agent (Collector).

**For the Manager:**
```bash
cd manager
pip install -r requirements_manager.txt
```

**For the Agent::**
```bash
cd agent
pip install -r requirements_agent.txt
```

### 4. Database Initialization
Create the database in PostgreSQL:
```bash
CREATE DATABASE traffix_db;
```
Then run the initialization script to generate the schema:
```bash
python manager/database.py
```

## 🚦 How to Run
###Step 1: Start the Manager
The manager handles the API, database storage, and serves the dashboard.

```bash
cd manager
python manager.py
```

### Step 2: Start the Agent
The agent requires administrative privileges to sniff network interfaces.

```bash
cd agent
python agent.py
```

### Step 3: Access the Dashboard
Once the Manager is running, open your browser and navigate to:
http://localhost:8000/dashboard/

## ⚙️ Administrative Controls
Hot-Reloading Config: The config.json file supports live updates for blacklists and agent names without restarting the server.

Safe Database Reset: A dedicated admin button to clear logs while preserving the database schema, protected by thread-level synchronization to avoid UniqueViolation errors.

## 🖥️ UI & Administrative Controls
Interactive Filtering: Filter all charts and tables by specific Agent or custom Time Range (e.g., Last 15m, 24h, 1y).

Reset Database: A built-in administrative button to wipe and rebuild the database schema. Includes a safety confirmation dialog to prevent accidental data loss.

Professional UI: Rounded "capsule" filter box, responsive grid layout, and custom-designed scrollbars.





<img width="1886" height="659" alt="image" src="https://github.com/user-attachments/assets/1bd8ebfa-58f0-4d16-ac5d-2af5d6372bb2" />

<img width="1890" height="546" alt="image" src="https://github.com/user-attachments/assets/80e7ac37-070f-4d89-a8bd-511ae68bce6d" />

<img width="1875" height="461" alt="image" src="https://github.com/user-attachments/assets/630d10d0-9e63-4235-9908-b4f669016df2" />

