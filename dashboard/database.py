import sqlite3
import os
from datetime import datetime

DB_PATH = "dashboard/ids.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs("dashboard", exist_ok=True)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            protocol    INTEGER,
            length      INTEGER,
            flags       TEXT,
            prediction  TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            src_ip      TEXT,
            dst_ip      TEXT,
            attack_type TEXT,
            severity    TEXT,
            verdict     TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sandbox_jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            payload     TEXT,
            verdict     TEXT,
            output      TEXT,
            job_id      TEXT
        )
    ''')

    conn.commit()
    conn.close()

def insert_packet(packet: dict):
    conn = get_connection()
    conn.execute('''
        INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, prediction)
        VALUES (:timestamp, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :length, :flags, :prediction)
    ''', packet)
    conn.commit()
    conn.close()

def insert_alert(alert: dict):
    conn = get_connection()
    conn.execute('''
        INSERT INTO alerts (timestamp, src_ip, dst_ip, attack_type, severity, verdict)
        VALUES (:timestamp, :src_ip, :dst_ip, :attack_type, :severity, :verdict)
    ''', alert)
    conn.commit()
    conn.close()

def insert_sandbox_job(job: dict):
    conn = get_connection()
    conn.execute('''
        INSERT INTO sandbox_jobs (timestamp, payload, verdict, output, job_id)
        VALUES (:timestamp, :payload, :verdict, :output, :job_id)
    ''', job)
    conn.commit()
    conn.close()

def get_recent_packets(limit=50):
    conn = get_connection()
    rows = conn.execute('''
        SELECT * FROM packets ORDER BY id DESC LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_recent_alerts(limit=20):
    conn = get_connection()
    rows = conn.execute('''
        SELECT * FROM alerts ORDER BY id DESC LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_recent_sandbox_jobs(limit=20):
    conn = get_connection()
    rows = conn.execute('''
        SELECT * FROM sandbox_jobs ORDER BY id DESC LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_stats():
    conn = get_connection()
    total    = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    threats  = conn.execute("SELECT COUNT(*) FROM packets WHERE prediction != 'Normal Traffic'").fetchone()[0]
    benign   = conn.execute("SELECT COUNT(*) FROM packets WHERE prediction = 'Normal Traffic'").fetchone()[0]
    sandbox  = conn.execute("SELECT COUNT(*) FROM sandbox_jobs").fetchone()[0]
    dist     = conn.execute('''
        SELECT prediction, COUNT(*) as count
        FROM packets
        GROUP BY prediction
    ''').fetchall()
    conn.close()
    return {
        "total":    total,
        "threats":  threats,
        "benign":   benign,
        "sandbox":  sandbox,
        "distribution": [dict(row) for row in dist]
    }
