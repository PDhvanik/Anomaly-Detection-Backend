import time
import os
import pandas as pd
import joblib
from scapy.all import get_working_if
from scapy.all import sniff, IP, TCP, UDP,IPv6,ARP,Ether
from collections import defaultdict
import time

base_dir = os.path.dirname(__file__)
model = joblib.load(os.path.join(base_dir, "anomaly_model.pkl"))
scaler = joblib.load(os.path.join(base_dir, "scaler.pkl"))
encoder = joblib.load(os.path.join(base_dir, "encoder.pkl"))

traffic_data = []
packet_counter = defaultdict(int)
last_seen = defaultdict(float)
RESULT_FILE = "anomaly_results.csv"


def packet_callback(packet):
    proto = "UNKNOWN"
    src = dst = "N/A"
    src_port = dst_port = 0

    
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        if packet.haslayer(TCP):
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

    
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = "IPv6"

        if packet.haslayer(UDP):
            proto = "UDPv6"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(TCP):
            proto = "TCPv6"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

    
    elif packet.haslayer(ARP):
        proto = "ARP"
        src = packet[ARP].psrc
        dst = packet[ARP].pdst

    elif packet.haslayer(Ether):
        proto = "Ethernet"

    timestamp = time.time()
    time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

    packet_counter[src] += 1
    last_seen[src] = time_str

    traffic_data.append({
        "Time": time_str,
        "Source": src,
        "Destination": dst,
        "Protocol": proto,
        "Length": len(packet),
        "Source Port": src_port,
        "Destination Port": dst_port
    })

    

    
    if len(traffic_data) >= 50:
        detect_anomaly(traffic_data.copy())
        traffic_data.clear()


def detect_anomaly(data):
    df = pd.DataFrame(data)
    
    protocol_encoded = encoder.transform(df[["Protocol"]])
    protocol_cols = [f"Protocol_{p}" for p in encoder.categories_[0]]

    
    numeric_features = ["Length", "Source Port", "Destination Port"]
    X = pd.concat([df[numeric_features].reset_index(drop=True),
                   pd.DataFrame(protocol_encoded, columns=protocol_cols)], axis=1)
    X.fillna(0, inplace=True)

    
    X_scaled = scaler.transform(X)

    
    df["Anomaly"] = model.predict(X_scaled)

    
    df.to_csv(RESULT_FILE, mode='a', header=not os.path.exists(
        RESULT_FILE), index=False)
    print(f"[+] {len(df)} packets analyzed and appended to {RESULT_FILE}")



try:
    print("[*] Capturing live traffic and detecting anomalies...")
    sniff(prn=packet_callback, store=0, iface=get_working_if())

except KeyboardInterrupt:
    print("\n[!] Capture stopped.")
