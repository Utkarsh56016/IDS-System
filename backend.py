# backend.py
from flask import Flask, jsonify, render_template
from sniffer import start_sniffer
import flow_manager
from flow_manager import extract_flow_features
from inference import model_predict_flow, threshold
import threading
import time
from collections import defaultdict

app = Flask(__name__)

alerts = []

# stats
packets_last = 0
last_calc_time = time.time()
anomaly_last_min = []   # only MEDIUM/HIGH anomalies counted


def classify_threat(src, dst, sport, dport, proto, sev, now):
    """Very simple rule-based threat category mapping using recent alerts."""
    window = 30.0
    recent = [a for a in alerts if now - a["time"] <= window]

    # Port scan: many distinct destination ports from same source in window (TCP)
    if proto == 6:  # TCP
        ports = {a["dport"] for a in recent if a["src_ip"] == src and a["proto"] == 6}
        ports.add(dport)
        if len(ports) >= 8:
            return "port_scan"

    # Broadcast storm: many multicast/broadcast destinations in window
    if dst == "MULTICAST" or dst.endswith(".255"):
        bcount = sum(1 for a in recent if a["dst_ip"] == dst)
        if bcount + 1 >= 10:
            return "broadcast_storm"

    # Suspicious ICMP traffic
    if proto == 1:
        return "suspicious_icmp"

    # DoS-like: many medium/high anomalies between same src/dst in window
    pair_recent = [
        a for a in recent
        if a["src_ip"] == src
        and a["dst_ip"] == dst
        and a.get("sev") in ["medium", "high"]
    ]
    pair_count = len(pair_recent)
    if sev in ["medium", "high"]:
        pair_count += 1
    if pair_count >= 10:
        return "dos_like"

    return "generic"


def analyzer():
    global packets_last, last_calc_time, anomaly_last_min

    print("Flow analyzer running...")

    recent_deltas = []

    while True:
        # Get flow vectors
        flow_vectors = extract_flow_features()
        now = time.time()
        elapsed = now - last_calc_time

        # ------------ PACKETS / SEC -------------
        if elapsed >= 1.0:
            # read/reset the authoritative counter inside the shared module
            packets_last = flow_manager.global_packet_counter / elapsed
            flow_manager.global_packet_counter = 0
            last_calc_time = now

        # ------------ PROCESS FLOWS -------------
        for fl in flow_vectors:
            fv = fl["features"]
            key = fl["key"]

            score, is_anomaly = model_predict_flow(fv)

            # compute delta
            delta = score - threshold
            recent_deltas.append(delta)
            if len(recent_deltas) > 15:
                recent_deltas.pop(0)

            strong_hits = sum(1 for d in recent_deltas if d > 0.08)

            # smoothing logic
            final_anomaly = False
            if delta > 0.02:
                final_anomaly = True
            if strong_hits >= 3:
                final_anomaly = True
            if delta < 0:
                final_anomaly = False

            # determine severity
            sev = "low"
            if delta > 0.15:
                sev = "high"
            elif delta > 0.05:
                sev = "medium"

            if final_anomaly:
                src, dst, sport, dport, proto = key

                category = classify_threat(src, dst, sport, dport, proto, sev, now)

                # store alert (keep list bounded by frontend slice)
                alerts.append({
                    "score": score,
                    "delta": delta,
                    "sev": sev,
                    "time": now,
                    "src_ip": src,
                    "dst_ip": dst,
                    "sport": sport,
                    "dport": dport,
                    "proto": proto,
                    "category": category
                })

                # count only MEDIUM/HIGH anomalies
                if sev in ["medium", "high"]:
                    anomaly_last_min.append(now)
                    anomaly_last_min = [t for t in anomaly_last_min if now - t <= 60]

        time.sleep(0.5)


# Start threads (sniffer + analyzer)
threading.Thread(target=start_sniffer, daemon=True).start()
threading.Thread(target=analyzer, daemon=True).start()


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/get_alerts")
def get_alerts():
    return jsonify(alerts[-200:])


@app.route("/get_stats")
def get_stats():
    return jsonify({
        "pps": round(packets_last, 2),
        "anoms_min": len(anomaly_last_min)
    })


@app.route("/get_top_talkers")
def get_top_talkers():
    top = flow_manager.get_top_talkers(limit=10)
    return jsonify(top)


@app.route("/get_protocol_counts")
def get_protocol_counts():
    counts = flow_manager.get_protocol_counts()
    return jsonify(counts)


if __name__ == "__main__":
    # run Flask only when executed as the main program
    app.run(host="0.0.0.0", port=5000, debug=False)
