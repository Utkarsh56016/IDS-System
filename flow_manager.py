# flow_manager.py
import time
from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP

# Flow store and window
flows = defaultdict(list)
WINDOW_SECONDS = 2

# Global packet counter (single authoritative variable)
global_packet_counter = 0

# Per-IP statistics for Top Talkers
ip_stats = defaultdict(lambda: {"bytes": 0, "packets": 0, "flows": set()})

# Protocol counters (simple totals since startup)
proto_counts = defaultdict(int)


def get_flow_key(pkt):
    """
    Returns normalized 5-tuple (src, dst, sport, dport, proto)
    Returns None for non-IP packets.
    Multicast/broadcast flows are normalized to reduce explosion.
    """
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = ip.proto
    src = ip.src
    dst = ip.dst

    sport = 0
    dport = 0

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    # Normalize multicast/broadcast into a single bucket to avoid huge numbers
    if dst.startswith("224.") or dst == "255.255.255.255":
        dst = "MULTICAST"
        # common normalization for mDNS
        sport = 5353
        dport = 5353

    return (src, dst, sport, dport, proto)


def add_packet(pkt):
    """
    Called by sniffer for every captured packet.
    Stores minimal info needed for feature extraction and increments counter.
    """
    global global_packet_counter

    key = get_flow_key(pkt)
    if not key:
        return

    global_packet_counter += 1

    # Update protocol counters
    src, dst, sport, dport, proto = key
    proto_counts[proto] += 1

    # Update per-IP stats (both src and dst)
    plen = len(pkt)

    sstat = ip_stats[src]
    sstat["packets"] += 1
    sstat["bytes"] += plen
    sstat["flows"].add(key)

    dstat = ip_stats[dst]
    dstat["packets"] += 1
    dstat["bytes"] += plen
    dstat["flows"].add(key)

    flags = None
    if TCP in pkt:
        flags = pkt[TCP].flags

    flows[key].append({
        "time": time.time(),
        "len": len(pkt),
        "flags": flags
    })


def extract_flow_features():
    """
    Build statistical vectors from flows. Each entry:
    { "key": (src,dst,sport,dport,proto), "features": [37-length vector] }
    """
    now = time.time()
    flow_vectors = []
    keys_to_delete = []

    # Iterate over a snapshot to avoid 'dictionary changed size during iteration'
    for key, plist in list(flows.items()):
        # Keep only packets inside the flow window
        recent = [p for p in plist if now - p["time"] <= WINDOW_SECONDS]

        if not recent:
            keys_to_delete.append(key)
            continue

        times = [p["time"] for p in recent]
        sizes = [p["len"] for p in recent]

        duration = max(times) - min(times) if times else 0
        total_packets = len(recent)
        total_bytes = sum(sizes)
        avg_pkt_size = total_bytes / total_packets if total_packets else 0
        max_pkt = max(sizes) if sizes else 0
        min_pkt = min(sizes) if sizes else 0

        inter = []
        for i in range(1, len(times)):
            inter.append(times[i] - times[i - 1])
        avg_inter = sum(inter) / len(inter) if inter else 0

        # Flags extraction (safe)
        syn = ack = rst = fin = 0
        for p in recent:
            f = p["flags"]
            if f is None:
                continue
            if not hasattr(f, "value"):
                continue
            fv = f.value
            if fv & 0x02: syn += 1
            if fv & 0x10: ack += 1
            if fv & 0x04: rst += 1
            if fv & 0x01: fin += 1

        fv = [
            duration,
            total_packets,
            total_bytes,
            avg_pkt_size,
            max_pkt,
            min_pkt,
            avg_inter,
            syn, ack, rst, fin
        ]

        # pad to 37 features (model expects this)
        while len(fv) < 37:
            fv.append(0)

        flow_vectors.append({
            "key": key,
            "features": fv
        })

    # cleanup inactive flows (keys may already be gone if packets arrived concurrently)
    for k in keys_to_delete:
        flows.pop(k, None)

    return flow_vectors


def get_top_talkers(limit=10):
    """Return a list of top talkers by bytes: [{ip, bytes, packets, flows}, ...]."""
    snapshot = list(ip_stats.items())
    rows = []
    for ip, stats in snapshot:
        rows.append({
            "ip": ip,
            "bytes": stats["bytes"],
            "packets": stats["packets"],
            "flows": len(stats["flows"]),
        })

    rows.sort(key=lambda r: r["bytes"], reverse=True)
    return rows[:limit]


def get_protocol_counts():
    """Return a dict mapping protocol number to packet count."""
    return dict(proto_counts)
