from scapy.all import sniff, IP

def show(pkt):
    if IP in pkt:
        print("IP Packet:", pkt[IP].src, "→", pkt[IP].dst)

sniff(prn=show, count=5)
