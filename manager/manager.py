import json
import socketserver
import sys
import threading
import asyncio
import time
from fastapi.staticfiles import StaticFiles
import os
from database import engine, Base
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from collections import defaultdict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, text
from database import SessionLocal, Agent, TrafficLog, BlacklistAlert
from config import config

# --- Global Locks and State ---
# This lock prevents race conditions between the Agent's INSERTs and the Admin's RESET
db_lock = threading.Lock()

active_connections = []
port_scan_tracker = defaultdict(set)
last_alert_time = {}
SCAN_THRESHOLD = 20
SCAN_WINDOW = 60
main_loop = None

# --- Application Lifespan Management ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure tables exist on startup
    Base.metadata.create_all(bind=engine)
    global main_loop
    main_loop = asyncio.get_running_loop()
    yield

app = FastAPI(lifespan=lifespan)
LISTEN_IP, LISTEN_PORT = config.get_server_settings()

# Security: Enable CORS for dashboard frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

dashboard_path = os.path.join(os.path.dirname(__file__), "../dashboard")
app.mount("/dashboard", StaticFiles(directory=dashboard_path, html=True), name="dashboard")

async def broadcast_packet(packet_data):
    """Push real-time updates to all connected WebSocket clients."""
    if not active_connections:
        return
    for connection in list(active_connections):
        try:
            await connection.send_json(packet_data)
        except Exception:
            if connection in active_connections:
                active_connections.remove(connection)

def detect_port_scan(agent_ip, target_ip, port):
    """Heuristic logic to identify sequential port scanning behavior."""
    key = (agent_ip, target_ip)
    port_scan_tracker[key].add(port)
    
    if len(port_scan_tracker[key]) > SCAN_THRESHOLD:
        now = time.time()
        if key not in last_alert_time or now - last_alert_time[key] > SCAN_WINDOW:
            last_alert_time[key] = now
            port_scan_tracker[key] = set() 
            return True
    return False

class UDPDataHandler(socketserver.BaseRequestHandler):
    """Backend handler for raw UDP data sent by network agents."""
    def handle(self):
        raw_data = self.request[0].strip()
        agent_ip = self.client_address[0]
        try:
            payload = json.loads(raw_data.decode('utf-8'))
        except: return

        # Synchronize DB access to avoid UniqueViolation during Reset
        with db_lock:
            db = SessionLocal()
            try:
                # Upsert logic for network agents
                agent = db.query(Agent).filter(Agent.ip_address == agent_ip).first()
                if not agent:
                    worker_name = config.get_agent_name(agent_ip)
                    agent = Agent(ip_address=agent_ip, mac_address=payload.get("mac", "Unknown"), name=f"Agent_{worker_name}")
                    db.add(agent)
                    db.commit()
                    db.refresh(agent)

                # Map incoming payload to database schema
                target_ip = payload.get("destination_ip")
                traffic = TrafficLog(
                    agent_id=agent.id, direction=payload.get("direction"),
                    destination_ip=target_ip, port=payload.get("port"),
                    size_bytes=payload.get("size_bytes"), country=payload.get("country"),
                    software_name=payload.get("software_name")
                )
                db.add(traffic)

                # Threat Detection: Blacklist matching
                if traffic.direction == "out" and target_ip in config.get_blacklist():
                    db.add(BlacklistAlert(agent_id=agent.id, destination_ip=target_ip))
                    payload["alert"] = True
                
                # Threat Detection: Port scanning
                if detect_port_scan(agent_ip, target_ip, payload.get("port")):
                    db.add(BlacklistAlert(agent_id=agent.id, destination_ip=f"PORT SCAN: {target_ip}"))
                    payload["security_event"] = "Port Scan Detected"
                    payload["alert"] = True

                db.commit()
                payload["agent_id"] = agent.id
                
                # Offload WebSocket broadcasting to the main async loop
                if main_loop:
                    asyncio.run_coroutine_threadsafe(broadcast_packet(payload), main_loop)
            except Exception as e:
                print(f"[!] DB Handler Error: {e}")
                db.rollback()
            finally:
                db.close()

# --- REST API Endpoints ---

@app.get("/api/agents")
async def get_agents():
    db = SessionLocal()
    try:
        agents = db.query(Agent).all()
        return [{"id": a.id, "name": a.name, "ip": a.ip_address} for a in agents]
    finally:
        db.close()


@app.get("/api/stats/{agent_id}")
async def get_stats(agent_id: str, timeframe: str = "all"):
    db = SessionLocal()
    try:
        query = db.query(TrafficLog)
        if agent_id != "all":
            query = query.filter(TrafficLog.agent_id == int(agent_id))
        
        if timeframe != "all":
            now = datetime.now(timezone.utc)
            offsets = {
                "15m": timedelta(minutes=15), "30m": timedelta(minutes=30),
                "1h": timedelta(hours=1), "2h": timedelta(hours=2),
                "5h": timedelta(hours=5), "24h": timedelta(hours=24),
                "36h": timedelta(hours=36), "48h": timedelta(hours=48),
                "1w": timedelta(weeks=1), "2w": timedelta(weeks=2),
                "1M": timedelta(days=30), "3M": timedelta(days=90),
                "1y": timedelta(days=365)
            }
            if timeframe in offsets:
                query = query.filter(TrafficLog.timestamp >= now - offsets[timeframe])

        countries = [{"label": r[0], "value": r[1]} for r in query.with_entities(TrafficLog.country, func.count(TrafficLog.id)).group_by(TrafficLog.country).all()]
        softwares = [{"label": r[0], "value": r[1]} for r in query.with_entities(TrafficLog.software_name, func.count(TrafficLog.id)).group_by(TrafficLog.software_name).all()]
        ips = [{"label": r[0], "value": r[1]} for r in query.with_entities(TrafficLog.destination_ip, func.count(TrafficLog.id)).group_by(TrafficLog.destination_ip).order_by(func.count(TrafficLog.id).desc()).limit(10).all()]
        bandwidth = [{"label": r[0], "value": round(r[1] / (1024 * 1024), 2)} for r in query.with_entities(TrafficLog.software_name, func.sum(TrafficLog.size_bytes)).group_by(TrafficLog.software_name).order_by(func.sum(TrafficLog.size_bytes).desc()).limit(5).all() if r[1]]
        top_processes = [{"name": r[0], "count": r[1]} for r in query.with_entities(TrafficLog.software_name, func.count(TrafficLog.id)).group_by(TrafficLog.software_name).order_by(func.count(TrafficLog.id).desc()).limit(10).all()]

        return {
            "countries": countries, "softwares": softwares,
            "ips": ips, "bandwidth": bandwidth, "top_processes": top_processes
        }
    finally:
        db.close()

@app.post("/api/admin/reset-db")
async def reset_db():
    # Define the sync reset function to run in executor
    def perform_reset():
        with db_lock: # Lock the DB while we truncate
            db = SessionLocal()
            try:
                db.execute(text("TRUNCATE TABLE blacklist_alerts, traffic_logs, agents RESTART IDENTITY CASCADE;"))
                db.commit()
                port_scan_tracker.clear()
                last_alert_time.clear()
            finally:
                db.close()

    try:
        loop = asyncio.get_running_loop()
        # Offload the blocking DB lock operation to a thread executor
        await loop.run_in_executor(None, perform_reset)
        return {"status": "success", "message": "Database has been completely reset."}
    except Exception as e:
        print(f"Error during TRUNCATE: {e}")
        return {"status": "error", "message": str(e)}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True: 
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    threading.Thread(target=lambda: socketserver.ThreadingUDPServer((LISTEN_IP, LISTEN_PORT), UDPDataHandler).serve_forever(), daemon=True).start()
    
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="error")