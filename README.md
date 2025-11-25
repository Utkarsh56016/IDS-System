
# Lightweight ML-Based Network Anomaly Detection System  
Real-time flow-based IDS with unsupervised ML, alert engine & live web dashboard.  
Author: Utkarsh Mishra (utkarshmishrahe0450@gmail.com)

---

## 🔥 Overview  
This project is a **Lightweight Anomaly-Based Intrusion Detection System (IDS)** designed for  
small networks such as home WiFi, labs, IoT environments, and student setups.

It performs **real-time packet capture**, builds **flow-level behavioral features**, and uses an  
**Isolation Forest ML model** to detect unusual or suspicious activities — including  
**zero-day attacks, port scans, ICMP storms, DoS-like patterns**, and abnormal traffic bursts.

The system includes:  
- Real-time packet sniffer (Scapy)  
- Flow builder with 37-D feature extraction  
- Lightweight ML inference engine  
- Threshold + severity scoring  
- Rule-based event categorization  
- Live dashboard (Flask + Chart.js)  
- Alerts, protocol stats, PPS graph & top-talkers  

---

## 🎯 Features  

### ✔ Real-Time Anomaly Detection  
- Uses flow-based statistical features (37 dimensions)  
- Unsupervised Isolation Forest model  
- Catches unknown & zero-day behavior patterns  

### ✔ Automatic Interface Selection (Windows-friendly)  
- Detects active WiFi/Ethernet adapters  
- Avoids virtual/loopback/Npcap ghost interfaces  
- No manual configuration required  

### ✔ Clean, Live Web Dashboard  
- Packets/sec timeline  
- Protocol distribution  
- Anomaly score graph  
- Categorized alerts (port scan, ICMP, DoS-like, etc.)  
- Top Talkers (IP + Bytes + Packets + Flows)  
- CSV export for offline analysis  

### ✔ Lightweight & Zero-Cost  
- Runs fully on Python  
- No external databases  
- No cloud services required  
- Can run on laptops or Raspberry Pi  

---

## 📦 Project Structure  

IDS-System/
│
├── backend.py # Flask backend + analyzer thread
├── sniffer.py # Packet capture and interface selection
├── flow_manager.py # Flow building + feature extraction
├── inference.py # ML model inference + scoring
│
├── model.pkl # IsolationForest model
├── scaler.pkl # StandardScaler object
├── threshold.pkl # Tuned anomaly threshold
│
├── static/
│ ├── dashboard.js # Frontend logic
│ └── style.css # UI styling
│
└── templates/
└── dashboard.html # Web dashboard UI

---

## 🚀 Getting Started

### 1️⃣ Install Dependencies  

```bash

pip install -r requirements.txt
---

### 2️⃣ Run the IDS  

python backend.py

The system will:  
- Auto-select the correct network interface  
- Start the sniffer & analyzer threads  
- Launch the dashboard backend  

Open the dashboard at:

http://127.0.0.1:5000

---

## 🔍 How It Works

### **1. Packet Capture**  
Scapy captures packets from LAN/WiFi in real time.

### **2. Flow Aggregation**  
Packets are grouped into flows (5-tuple):  
`src_ip, dst_ip, src_port, dst_port, protocol`

### **3. 37-D Feature Extraction**  
Features include:  
- Duration, packet count, byte count  
- Inter-arrival statistics  
- Packet size stats  
- TCP SYN/ACK/RST/FIN flags  
- Directional ratios  
- Port & protocol info  

### **4. ML Inference**  
Isolation Forest evaluates anomaly score:  
`score = -model.decision_function(scaled_features)`

### **5. Alert Engine**  
Outputs:  
- Severity (low/medium/high)  
- Category (port_scan / suspicious_icmp / dos_like / broadcast_storm / generic)  

### **6. Visualization**  
The dashboard polls backend APIs every 1–2 seconds.

---

## 🌱 Roadmap (Future Work)  
- Database logging (SQLite/MongoDB)  
- Multi-node distributed sensors  
- TLS + authentication for dashboard  
- Advanced ML models (LSTM / Autoencoders)  
- DPI module for deeper traffic analysis  

---

## 📄 License  
Released under the **MIT License**.  
Free to use, modify, and distribute with attribution.

---

## 👤 Author  

**Utkarsh Mishra**  
📧 Email: utkarshmishrahe0450@gmail.com  

If this project helped you, consider giving the repository a ⭐ on GitHub!






