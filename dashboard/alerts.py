from datetime import datetime
from dashboard.database import insert_alert, insert_sandbox_job
from sandbox.client import send_to_sandbox

SEVERITY_MAP = {
    "Normal Traffic": None,
    "Port Scanning":  "medium",
    "DDoS":           "critical",
    "DoS":            "critical",
    "Brute Force":    "high",
    "Botnet":         "high",
    "Web Attack":     "medium",
}

def process_prediction(packet: dict, prediction: str):
    if prediction == "BENIGN" or prediction == "Normal Traffic":
    	return

    severity = SEVERITY_MAP.get(prediction, "medium")
    src = packet.get('src_ip', '')
    dst = packet.get('dst_ip', '')
    payload = f"print('src={src} dst={dst} type={prediction}')"
    result   = send_to_sandbox(payload)

    insert_sandbox_job({
        "timestamp": datetime.now().isoformat(),
        "payload":   payload,
        "verdict":   result.get("verdict", "unknown"),
        "output":    result.get("output", ""),
        "job_id":    result.get("job_id", ""),
    })

    if result.get("verdict") == "malicious":
        insert_alert({
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      packet.get("src_ip", "unknown"),
            "dst_ip":      packet.get("dst_ip", "unknown"),
            "attack_type": prediction,
            "severity":    severity,
            "verdict":     "confirmed",
        })
        print(f"[!!!] CONFIRMED THREAT: {prediction} from {packet.get('src_ip')} — severity: {severity}")
    else:
        insert_alert({
            "timestamp":   datetime.now().isoformat(),
            "src_ip":      packet.get("src_ip", "unknown"),
            "dst_ip":      packet.get("dst_ip", "unknown"),
            "attack_type": prediction,
            "severity":    severity,
            "verdict":     "false_positive",
        })
        print(f"[~] False positive cleared: {prediction} from {packet.get('src_ip')}")
