# sniffer.py
from scapy.all import sniff, get_if_list, get_if_addr
import flow_manager
import time
import os

def packet_handler(pkt):
    """
    Called by Scapy for each packet. Adds to flow_manager.
    """
    try:
        flow_manager.add_packet(pkt)
    except Exception:
        # swallow exceptions from malformed packets
        pass

def choose_interface():
    """
    Choose a capture interface on Windows.

    Rules:
    - If IDS_SNIFFER_IFACE env var is set, use that directly.
    - Otherwise, prefer real LAN/Wi-Fi adapters based on name keywords.
    - Exclude loopback / virtual / Hyper-V / Npcap loopback style adapters.
    - If no name-based match, fall back to a non-loopback interface.
    - Among candidates, prefer those with an assigned IPv4 address (not 0.0.0.0).
    - Never default to loopback if any other interface exists.
    """
    # Optional manual override for tricky Windows setups
    env_iface = os.environ.get("IDS_SNIFFER_IFACE")
    if env_iface:
        print("Using IDS_SNIFFER_IFACE override:", env_iface)
        return env_iface

    valid_keywords = ["wi-fi", "wifi", "ethernet", "lan", "wlan", "intel", "realtek", "qualcomm"]
    invalid_keywords = ["loopback", "npcap", "vmnet", "hyper-v", "virtual", "bridge"]

    def is_invalid_name(lname: str) -> bool:
        # Explicitly avoid common loopback identifiers
        if lname in ("lo", "lo0"):
            return True
        return any(bad in lname for bad in invalid_keywords)

    def has_ipv4(name: str) -> bool:
        try:
            ip = get_if_addr(name)
        except Exception:
            return False
        if not ip or ip == "0.0.0.0":
            return False
        return True

    def get_ip(name: str) -> str | None:
        try:
            ip = get_if_addr(name)
        except Exception:
            return None
        if not ip or ip == "0.0.0.0":
            return None
        return ip

    def ip_score(ip: str | None) -> int:
        """Rough priority for IPv4 addresses on Windows.

        Higher score = more preferred.
        - 0: no/invalid IP
        - 1: loopback/link-local (127.x, 169.254.x)
        - 2: other valid IPv4
        - 3: private LAN ranges (10/8, 172.16-31/12, 192.168/16)
        """
        if not ip:
            return 0
        if ip == "0.0.0.0":
            return 0
        if ip.startswith("127.") or ip.startswith("169.254."):
            return 1

        # Private ranges get highest priority
        if ip.startswith("10.") or ip.startswith("192.168."):
            return 3
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) >= 2:
                try:
                    second = int(parts[1])
                    if 16 <= second <= 31:
                        return 3
                except ValueError:
                    pass

        # Any other usable IPv4
        return 2

    def select_best_by_ip(names: list[str]) -> str | None:
        best = None
        best_score = -1
        for n in names:
            score = ip_score(get_ip(n))
            if score > best_score:
                best_score = score
                best = n
        if best is not None:
            return best
        return names[0] if names else None

    ifs = get_if_list()
    print("Available interfaces:")
    for name in ifs:
        try:
            ip = get_if_addr(name)
        except Exception:
            ip = "N/A"
        print(f" - {name} -> {ip}")

    # First pass: by descriptive name
    name_candidates = []
    for name in ifs:
        lname = name.lower()
        if is_invalid_name(lname):
            continue
        if any(good in lname for good in valid_keywords):
            name_candidates.append(name)

    # Prefer name-based candidates with IPv4
    candidates: list[str] = []
    if name_candidates:
        ipv4_candidates = [n for n in name_candidates if has_ipv4(n)]
        candidates = ipv4_candidates or name_candidates
    else:
        # Second pass: any non-loopback, non-virtual interface
        non_loopback = [n for n in ifs if not is_invalid_name(n.lower())]
        if non_loopback:
            ipv4_non_loopback = [n for n in non_loopback if has_ipv4(n)]
            candidates = ipv4_non_loopback or non_loopback

    # Final selection: prefer private LAN / non-link-local IPv4s
    if candidates:
        iface = select_best_by_ip(candidates)
    else:
        # if absolutely nothing else, allow whatever Scapy reports first
        iface = ifs[0] if ifs else None
    print("Selected interface:", iface)
    return iface

def start_sniffer():
    """
    Starts the packet sniffer. Runs blocking; call from background thread.
    """
    try:
        iface = choose_interface()
    except Exception:
        iface = None

    print("Sniffer using interface:", iface)
    # Always prefer an explicitly chosen interface; if None, let Scapy decide
    if iface:
        sniff(prn=packet_handler, store=False, iface=iface)
    else:
        sniff(prn=packet_handler, store=False)
