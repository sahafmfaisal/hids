"""
HIDS Monitor Daemon — persistent background service.
Writes to SQLite via db.py, state.json for dashboard polling.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import time, json, uuid, random, logging
from datetime import datetime
from core.db import insert_alert, upsert_session, tick_scan, ensure_db

STATE_FILE   = os.environ.get("HIDS_STATE",  "/var/lib/hids/state.json")
SIGNAL_FILE  = "/tmp/hids_attack_signal"
SCAN_INTERVAL   = 2
BASELINE_SCANS  = 12
DEDUP_WINDOW    = 10

logging.basicConfig(
    filename="/var/log/hids/monitor.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

SCENARIO_FEATURES = {
    1: {"open_count":38,"read_count":112,"write_count":0,"exec_count":4,
        "privilege_used":0,"delete_count":0,"chmod_count":0,
        "sensitive_hits":7,"sudoers_hits":0,"log_hits":0,"bulk_operation":1},
    2: {"open_count":42,"read_count":98,"write_count":0,"exec_count":3,
        "privilege_used":1,"delete_count":0,"chmod_count":0,
        "sensitive_hits":5,"sudoers_hits":2,"log_hits":0,"bulk_operation":1},
    3: {"open_count":61,"read_count":240,"write_count":312,"exec_count":6,
        "privilege_used":0,"delete_count":52,"chmod_count":0,
        "sensitive_hits":0,"sudoers_hits":0,"log_hits":0,"bulk_operation":1},
    4: {"open_count":29,"read_count":88,"write_count":74,"exec_count":8,
        "privilege_used":0,"delete_count":0,"chmod_count":0,
        "sensitive_hits":3,"sudoers_hits":0,"log_hits":0,"bulk_operation":1},
    5: {"open_count":18,"read_count":64,"write_count":4,"exec_count":2,
        "privilege_used":0,"delete_count":2,"chmod_count":2,
        "sensitive_hits":2,"sudoers_hits":0,"log_hits":3,"bulk_operation":0},
}

THREAT_META = {
    "LOG TAMPERING / ANTI-FORENSICS":     ("CRITICAL","T1070",  "Indicator Removal on Host"),
    "DATA EXFILTRATION + CLEANUP":        ("HIGH",    "T1560",  "Archive Collected Data"),
    "BULK DATA EXFILTRATION":             ("HIGH",    "T1560",  "Archive Collected Data"),
    "SUSPICIOUS SCRIPT EXECUTION (LotL)": ("HIGH",    "T1059",  "Command & Scripting Interpreter"),
    "PRIVILEGE ESCALATION":               ("HIGH",    "T1078",  "Valid Accounts / Abuse Elevation"),
    "SENSITIVE FILE RECONNAISSANCE":      ("MEDIUM",  "T1087",  "Account Discovery"),
    "FILE DELETION / ANTI-FORENSICS":     ("HIGH",    "T1070.004","File Deletion"),
    "ANOMALOUS BEHAVIOUR":                ("LOW",     "T1036",  "Masquerading"),
}

def classify(f):
    w,d,c = f.get("write_count",0), f.get("delete_count",0), f.get("chmod_count",0)
    sh,su,lh = f.get("sensitive_hits",0), f.get("sudoers_hits",0), f.get("log_hits",0)
    if c>0 or (lh>0 and d>0): return "LOG TAMPERING / ANTI-FORENSICS"
    if lh>=2:                  return "LOG TAMPERING / ANTI-FORENSICS"
    if w>100 and d>5:          return "DATA EXFILTRATION + CLEANUP"
    if w>100:                  return "BULK DATA EXFILTRATION"
    if sh>=1 and w>20:         return "SUSPICIOUS SCRIPT EXECUTION (LotL)"
    if su>=1:                  return "PRIVILEGE ESCALATION"
    if sh>=2 and w<15:         return "SENSITIVE FILE RECONNAISSANCE"
    if sh>=1 and w<15 and d==0 and c==0: return "SENSITIVE FILE RECONNAISSANCE"
    if d>20:                   return "FILE DELETION / ANTI-FORENSICS"
    return "ANOMALOUS BEHAVIOUR"

def check_signal():
    if not os.path.exists(SIGNAL_FILE):
        return None
    try:
        with open(SIGNAL_FILE) as f:
            n = int(f.read().strip())
        os.remove(SIGNAL_FILE)
        feats  = SCENARIO_FEATURES.get(n, SCENARIO_FEATURES[1])
        threat = classify(feats)
        sev, mid, mname = THREAT_META.get(threat, ("LOW","T1036","Masquerading"))
        return {"threat":threat,"severity":sev,"confidence":round(0.93+n*0.01,2),
                "mitre_id":mid,"mitre_name":mname,"features":feats,"scenario":n}
    except Exception as e:
        logging.error(f"signal: {e}")
        try: os.remove(SIGNAL_FILE)
        except: pass
        return None

def idle_features():
    return {"open_count":random.randint(2,8),"read_count":random.randint(4,15),
            "write_count":random.randint(0,3),"exec_count":random.randint(0,2),
            "privilege_used":0,"delete_count":0,"chmod_count":0,
            "sensitive_hits":0,"sudoers_hits":0,"log_hits":0,"bulk_operation":0}

def write_state(s):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp,"w") as f:
        json.dump(s, f)
    os.replace(tmp, STATE_FILE)

def run():
    ensure_db()
    os.makedirs("/var/log/hids", exist_ok=True)
    if os.path.exists(SIGNAL_FILE):
        os.remove(SIGNAL_FILE)

    session_id   = str(uuid.uuid4())[:8]
    scan_count   = 0
    last_alert_t = None
    last_alert   = None
    stats = {"alerts":0,"suppressed":0,"scans":0,"syscalls":0}
    session_start = datetime.now().isoformat()

    logging.info(f"Monitor started session={session_id}")

    while True:
        scan_count += 1
        stats["scans"] += 1
        stats["syscalls"] += random.randint(350,620)
        now  = datetime.now()
        hour = now.strftime("%Y-%m-%dT%H")
        tick_scan(hour)

        is_calib = scan_count <= BASELINE_SCANS
        signal   = check_signal() if not is_calib else None
        in_dedup = last_alert_t and (now - last_alert_t).total_seconds() < DEDUP_WINDOW

        if is_calib:
            status = "calibrating"

        elif signal and in_dedup:
            stats["suppressed"] += 1
            evt = {**signal, "suppressed":True,
                   "timestamp":now.isoformat(), "session_id":session_id,
                   "reason":f"Duplicate within {DEDUP_WINDOW}s dedup window"}
            insert_alert(evt)
            status = "suppressed"

        elif signal:
            stats["alerts"] += 1
            last_alert_t = now
            last_alert   = signal
            evt = {**signal, "suppressed":False,
                   "timestamp":now.isoformat(), "session_id":session_id}
            insert_alert(evt)
            status = "alert"
            logging.warning(f"ALERT {signal['threat']} conf={signal['confidence']}")

        elif in_dedup and last_alert:
            stats["suppressed"] += 1
            remaining = round(DEDUP_WINDOW - (now - last_alert_t).total_seconds(),1)
            evt = {**last_alert, "suppressed":True,
                   "timestamp":now.isoformat(), "session_id":session_id,
                   "reason":f"Threat persisting — {remaining}s in dedup window"}
            insert_alert(evt)
            status = "suppressed"

        else:
            status = "secure"

        upsert_session({
            "id":session_id,"started_at":session_start,
            "ended_at":now.isoformat(),
            "total_scans":scan_count,"total_alerts":stats["alerts"],
            "suppressed":stats["suppressed"],"syscalls":stats["syscalls"]
        })

        write_state({
            "status":status,"scan_count":scan_count,
            "timestamp":now.isoformat(),
            "baseline_progress":min(scan_count,BASELINE_SCANS),
            "features":idle_features() if status=="secure" else (last_alert or {}).get("features",{}),
            "last_alert":last_alert,
            "session_id":session_id,
            "stats":{**stats,"start":session_start},
        })

        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    run()
