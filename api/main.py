"""
DataDefenceX Web API - FastAPI Backend
Provides REST API and WebSocket support for real-time threat detection
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Dict, Optional
import asyncio
import json
import sys
import os
from datetime import datetime
from pydantic import BaseModel

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from realtime_main import RealtimeDetectionSystem, load_whitelist
from agent.agent_process_monitor import ProcessMonitorAgent
from agent.agent_memory_monitor import MemoryMonitorAgent
from agent.agent_yara_scanner import YARAScanner
from engine.engine_action import ActionEngine, ThreatLevel
import psutil

app = FastAPI(title="DataDefenceX API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global detection system instance
detection_system: Optional[RealtimeDetectionSystem] = None
detection_history: List[Dict] = []
websocket_connections: List[WebSocket] = []

# Pydantic models
class DetectionResponse(BaseModel):
    pid: int
    name: str
    path: str
    cmdline: str
    threat_score: float
    confidence: float
    threat_level: str
    indicators: List[str]
    timestamp: str

class ActionRequest(BaseModel):
    pid: int
    action: str  # "kill", "suspend", "block_network", "resume"

class ProcessInfo(BaseModel):
    pid: int
    name: str
    path: str
    cmdline: str
    ppid: Optional[int]
    status: str
    memory_mb: float
    cpu_percent: float

class SystemStats(BaseModel):
    processes_scanned: int
    memory_scans: int
    threats_detected: int
    actions_taken: int
    false_positives_avoided: int
    runtime_seconds: float
    is_running: bool

@app.on_event("startup")
async def startup_event():
    """Initialize detection system on startup"""
    global detection_system
    try:
        detection_system = RealtimeDetectionSystem()
        # Hook into detection system to capture detections
        original_print = detection_system._print_detection
        def hooked_print_detection(event_data, result, adjusted_score):
            original_print(event_data, result, adjusted_score)
            add_detection(event_data, result, adjusted_score)
        detection_system._print_detection = hooked_print_detection
        print("[*] Detection system initialized (not started)")
    except Exception as e:
        print(f"[!] Error initializing detection system: {e}")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "DataDefenceX API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "monitoring": "/api/monitoring",
            "detections": "/api/detections",
            "processes": "/api/processes",
            "stats": "/api/stats",
            "actions": "/api/actions"
        }
    }

@app.get("/api/stats")
async def get_stats() -> SystemStats:
    """Get system statistics"""
    global detection_system
    
    if not detection_system:
        return SystemStats(
            processes_scanned=0,
            memory_scans=0,
            threats_detected=0,
            actions_taken=0,
            false_positives_avoided=0,
            runtime_seconds=0,
            is_running=False
        )
    
    stats = detection_system.stats.copy()
    runtime = 0
    if stats.get('start_time'):
        runtime = (datetime.now() - stats['start_time']).total_seconds()
    
    return SystemStats(
        processes_scanned=stats.get('processes_scanned', 0),
        memory_scans=stats.get('memory_scans', 0),
        threats_detected=stats.get('threats_detected', 0),
        actions_taken=stats.get('actions_taken', 0),
        false_positives_avoided=stats.get('false_positives_avoided', 0),
        runtime_seconds=runtime,
        is_running=detection_system.running
    )

@app.post("/api/monitoring/start")
async def start_monitoring():
    """Start real-time monitoring"""
    global detection_system
    
    if not detection_system:
        detection_system = RealtimeDetectionSystem()
    
    if detection_system.running:
        return {"status": "already_running", "message": "Monitoring is already running"}
    
    # Start monitoring in background thread
    import threading
    def start_system():
        try:
            detection_system.start()
        except Exception as e:
            print(f"[!] Error in monitoring thread: {e}")
    
    thread = threading.Thread(target=start_system, daemon=True)
    thread.start()
    
    # Wait a moment to ensure it started
    await asyncio.sleep(1)
    
    return {
        "status": "started",
        "message": "Real-time monitoring started successfully"
    }

@app.post("/api/monitoring/stop")
async def stop_monitoring():
    """Stop real-time monitoring"""
    global detection_system
    
    if not detection_system or not detection_system.running:
        return {"status": "not_running", "message": "Monitoring is not running"}
    
    detection_system.stop()
    
    return {
        "status": "stopped",
        "message": "Monitoring stopped successfully"
    }

@app.get("/api/monitoring/status")
async def get_monitoring_status():
    """Get monitoring status"""
    global detection_system
    
    if not detection_system:
        return {"running": False, "message": "System not initialized"}
    
    return {
        "running": detection_system.running,
        "message": "Monitoring active" if detection_system.running else "Monitoring stopped"
    }

@app.get("/api/detections")
async def get_detections(limit: int = 50) -> List[DetectionResponse]:
    """Get recent detections"""
    global detection_history
    
    # Return most recent detections
    recent = detection_history[-limit:] if len(detection_history) > limit else detection_history
    return [DetectionResponse(**det) for det in recent]

@app.get("/api/processes")
async def get_processes() -> List[ProcessInfo]:
    """Get list of all running processes"""
    processes = []
    
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'status', 'cmdline']):
            try:
                info = proc.info
                pid = info['pid']
                
                # Get memory and CPU
                try:
                    proc_obj = psutil.Process(pid)
                    memory_mb = proc_obj.memory_info().rss / (1024 * 1024)
                    cpu_percent = proc_obj.cpu_percent(interval=0.1)
                except:
                    memory_mb = 0
                    cpu_percent = 0
                
                cmdline = ' '.join(info.get('cmdline', [])) if info.get('cmdline') else ''
                
                processes.append(ProcessInfo(
                    pid=pid,
                    name=info.get('name', 'unknown'),
                    path=info.get('exe', ''),
                    cmdline=cmdline[:200],  # Limit length
                    ppid=info.get('ppid'),
                    status=info.get('status', 'unknown'),
                    memory_mb=round(memory_mb, 2),
                    cpu_percent=round(cpu_percent, 2)
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        print(f"[!] Error getting processes: {e}")
    
    return processes

@app.get("/api/processes/{pid}")
async def get_process_details(pid: int) -> Dict:
    """Get detailed information about a specific process"""
    try:
        proc = psutil.Process(pid)
        
        # Get command line
        try:
            cmdline = ' '.join(proc.cmdline())
        except:
            cmdline = ''
        
        # Analyze process for threats
        threat_info = await analyze_process(pid)
        
        return {
            "pid": pid,
            "name": proc.name(),
            "path": proc.exe() if proc.exe() else '',
            "cmdline": cmdline,
            "ppid": proc.ppid(),
            "status": proc.status(),
            "memory_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
            "cpu_percent": proc.cpu_percent(interval=0.1),
            "create_time": datetime.fromtimestamp(proc.create_time()).isoformat(),
            "threads": proc.num_threads(),
            "open_files": len(proc.open_files()) if hasattr(proc, 'open_files') else 0,
            "connections": len(proc.connections()) if hasattr(proc, 'connections') else 0,
            "threat_analysis": threat_info
        }
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail="Process not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def analyze_process(pid: int) -> Dict:
    """Analyze a process for threats"""
    global detection_system
    
    if not detection_system or not detection_system.process_agent:
        return {"error": "Detection system not available"}
    
    try:
        proc = psutil.Process(pid)
        proc_info = {
            'pid': pid,
            'ppid': proc.ppid(),
            'name': proc.name(),
            'exe': proc.exe() if proc.exe() else '',
            'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else ''
        }
        
        # Analyze with process monitor
        event = detection_system.process_agent.analyze_process(proc_info)
        
        if event:
            return {
                "suspicious": True,
                "suspicion_score": event.suspicion_score,
                "indicators": event.suspicious_indicators,
                "threat_level": get_threat_level(event.suspicion_score)
            }
        else:
            return {
                "suspicious": False,
                "suspicion_score": 0,
                "indicators": [],
                "threat_level": "LOW"
            }
    except Exception as e:
        return {"error": str(e)}

def get_threat_level(score: float) -> str:
    """Convert score to threat level"""
    if score >= 90:
        return "CRITICAL"
    elif score >= 75:
        return "HIGH"
    elif score >= 60:
        return "MEDIUM"
    else:
        return "LOW"

@app.post("/api/actions")
async def take_action(request: ActionRequest) -> Dict:
    """Take action on a process (kill, suspend, etc.)"""
    global detection_system
    
    if not detection_system or not detection_system.action_engine:
        raise HTTPException(status_code=500, detail="Action engine not available")
    
    try:
        proc = psutil.Process(request.pid)
        process_info = {
            'pid': request.pid,
            'name': proc.name(),
            'path': proc.exe() if proc.exe() else '',
            'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else ''
        }
        
        # Determine threat level
        threat_level = ThreatLevel.MEDIUM  # Default
        
        # Get threat score from analysis
        analysis = await analyze_process(request.pid)
        if analysis.get('suspicion_score', 0) >= 90:
            threat_level = ThreatLevel.CRITICAL
        elif analysis.get('suspicion_score', 0) >= 75:
            threat_level = ThreatLevel.HIGH
        elif analysis.get('suspicion_score', 0) >= 60:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
        
        detection_details = {
            'threat_score': analysis.get('suspicion_score', 0),
            'confidence': 0.8,
            'indicators': analysis.get('indicators', [])
        }
        
        # Execute action
        if request.action == "kill":
            result = detection_system.action_engine._kill_process(request.pid, proc.name())
        elif request.action == "suspend":
            result = detection_system.action_engine._suspend_process(request.pid, proc.name())
        elif request.action == "resume":
            result = detection_system.action_engine.process_controller.resume_process(request.pid)
            return {"status": "success" if result else "failed", "action": "resume", "pid": request.pid}
        elif request.action == "block_network":
            result = detection_system.action_engine._block_network(request.pid, proc.name())
        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {request.action}")
        
        # Broadcast action to WebSocket clients
        await broadcast_message({
            "type": "action_taken",
            "pid": request.pid,
            "action": request.action,
            "success": result.success,
            "timestamp": datetime.now().isoformat()
        })
        
        return {
            "status": "success" if result.success else "failed",
            "action": request.action,
            "pid": request.pid,
            "message": result.message
        }
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail="Process not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/whitelist")
async def get_whitelist() -> Dict:
    """Get current whitelist configuration"""
    whitelist = load_whitelist()
    return whitelist

@app.post("/api/scan/process/{pid}")
async def scan_process(pid: int) -> Dict:
    """Manually scan a specific process"""
    global detection_system
    
    if not detection_system:
        raise HTTPException(status_code=500, detail="Detection system not available")
    
    try:
        # Analyze process
        analysis = await analyze_process(pid)
        
        # Scan memory if memory agent available
        memory_indicators = []
        if detection_system.memory_agent:
            try:
                memory_indicators = detection_system.memory_agent.scan_process(pid)
            except:
                pass
        
        return {
            "pid": pid,
            "process_analysis": analysis,
            "memory_indicators": len(memory_indicators),
            "timestamp": datetime.now().isoformat()
        }
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail="Process not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await websocket.accept()
    websocket_connections.append(websocket)
    
    try:
        # Send initial connection message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to DataDefenceX real-time updates"
        })
        
        # Keep connection alive and forward messages
        while True:
            data = await websocket.receive_text()
            # Echo back or handle commands
            await websocket.send_json({
                "type": "echo",
                "data": data
            })
    except WebSocketDisconnect:
        websocket_connections.remove(websocket)
    except Exception as e:
        print(f"[!] WebSocket error: {e}")
        if websocket in websocket_connections:
            websocket_connections.remove(websocket)

async def broadcast_message(message: Dict):
    """Broadcast message to all WebSocket clients"""
    disconnected = []
    for ws in websocket_connections:
        try:
            await ws.send_json(message)
        except:
            disconnected.append(ws)
    
    # Remove disconnected clients
    for ws in disconnected:
        if ws in websocket_connections:
            websocket_connections.remove(ws)

# Function to add detection to history (called from detection system)
def add_detection(event_data: Dict, result, adjusted_score: float):
    """Add detection to history"""
    global detection_history
    
    try:
        if event_data.get('type') == 'process':
            proc = event_data.get('event')
            if proc and hasattr(proc, 'pid'):
                detection = {
                    "pid": proc.pid,
                    "name": getattr(proc, 'name', 'Unknown'),
                    "path": getattr(proc, 'exe_path', ''),
                    "cmdline": (getattr(proc, 'cmdline', '') or '')[:200],
                    "threat_score": float(adjusted_score),
                    "confidence": float(getattr(result, 'confidence', 0) * 100),
                    "threat_level": get_threat_level(adjusted_score),
                    "indicators": getattr(result, 'contributing_features', [])[:5],
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return
        else:
            detection = {
                "pid": event_data.get('pid', 0),
                "name": event_data.get('name', 'Unknown'),
                "path": event_data.get('path', ''),
                "cmdline": '',
                "threat_score": float(adjusted_score),
                "confidence": float(getattr(result, 'confidence', 0) * 100),
                "threat_level": get_threat_level(adjusted_score),
                "indicators": getattr(result, 'contributing_features', [])[:5],
                "timestamp": datetime.now().isoformat()
            }
        
        detection_history.append(detection)
        
        # Keep only last 1000 detections
        if len(detection_history) > 1000:
            detection_history[:] = detection_history[-1000:]
        
        # Broadcast to WebSocket clients
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(broadcast_message({
                    "type": "detection",
                    "data": detection
                }))
            else:
                loop.run_until_complete(broadcast_message({
                    "type": "detection",
                    "data": detection
                }))
        except:
            pass  # WebSocket broadcast failed, continue
    except Exception as e:
        print(f"[!] Error adding detection to history: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

