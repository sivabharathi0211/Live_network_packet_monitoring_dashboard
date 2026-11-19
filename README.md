# 📡 Live Network Packet Monitoring Dashboard

A real-time network monitoring dashboard built with **Python and Flask** for visualizing authorized network traffic, monitoring packet metadata, discovering connected devices, and filtering traffic by protocol, IP address, port, and service type.

The project provides a beginner-friendly interface for understanding network activity while following a **privacy-conscious monitoring approach** by collecting packet metadata without displaying or storing packet payloads.


## 🚀 Project Overview

The Live Network Packet Monitoring Dashboard is a network monitoring application designed to help users observe and understand network traffic in real time.

It captures network packet metadata, identifies traffic characteristics, displays connected devices, and provides an interactive dashboard for monitoring network activity. Users can start or stop packet capture, inspect traffic statistics, and apply filters to analyze specific network communication.

The application is designed for educational purposes, cybersecurity learning, network monitoring, and authorized network analysis.


## ✨ Features

- **Real-Time Packet Monitoring** – Capture and monitor incoming and outgoing network traffic.
- **Interactive Dashboard** – Visualize network activity through a web-based interface.
- **Packet Metadata Analysis** – View source IP, destination IP, protocol, ports, packet size, timestamp, direction, and service type.
- **Connected Device Discovery** – Identify devices using IP addresses, MAC addresses, and hostnames when available.
- **Service Classification** – Categorize network traffic into HTTP, HTTPS, FTP, MySQL, and Other.
- **Traffic Filtering** – Filter packets based on IP address, protocol, port, and service category.
- **Capture Controls** – Start and stop packet capture directly from the dashboard.
- **Traffic Statistics** – Monitor packet counts and traffic volume.
- **Privacy-Conscious Design** – Capture metadata without displaying or storing packet payloads.
- **Local Dashboard** – Access the monitoring interface through a local Flask server.


## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core application development |
| Flask | Web application and dashboard backend |
| Scapy | Network packet capture and packet analysis |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Interactive dashboard functionality |
| Npcap | Windows packet capture support |


## 📊 Packet Information Monitored

The dashboard displays the following packet information:

| Field | Description |
|---|---|
| Source IP | IP address of the packet sender |
| Destination IP | IP address of the packet receiver |
| Protocol | Network protocol associated with the packet |
| Source Port | Port number used by the sender |
| Destination Port | Port number used by the receiver |
| Packet Size | Size of the captured packet |
| Timestamp | Time at which the packet was captured |
| Direction | Incoming or outgoing traffic direction |
| Service | Identified service category |


## 🌐 Service Classification

Network traffic is classified based on commonly associated port numbers.

| Service | Port Number |
|---|---|
| HTTP | 80 |
| HTTPS | 443 |
| FTP | 20, 21 |
| MySQL | 3306 |
| Other | Remaining traffic |


## 🖥️ Dashboard Capabilities

### Live Traffic Monitoring
Monitor network packets as they are captured from the selected network interface.

### Device Discovery
View discovered network devices, including their IP addresses, MAC addresses, and hostnames when available.

### Traffic Filtering
Narrow the displayed packet records using:

- IP Address
- Protocol
- Port
- Service Type

### Capture Management
Control the monitoring process using the dashboard's Start and Stop capture controls.

### Network Statistics
View packet totals and traffic volume to understand network activity.


## 📷 Dashboard Preview

Dashboard
<img width="1360" height="718" alt="Screenshot 2026-07-20 214128" src="https://github.com/user-attachments/assets/0a5253a3-05e5-4ec5-b43f-c7fbf6ecc398" />

Live Packet Monitoring
<img width="1361" height="672" alt="Screenshot 2026-07-20 214225" src="https://github.com/user-attachments/assets/a5bcf12d-521b-4caa-bb7f-825f70830d71" />

Traffic Filtering 
<img width="980" height="610" alt="image" src="https://github.com/user-attachments/assets/1dddff92-d8ed-4778-b5ff-27b431ecb39f" />

Service Split

<img width="326" height="586" alt="Screenshot 2026-07-20 224321" src="https://github.com/user-attachments/assets/1e436deb-5f17-45ed-9119-2020c8c12bf0" />


## ⚙️ Installation and Setup

### Prerequisites

- Python 3.x
- pip
- Administrator/root privileges for live packet capture when required
- Npcap installed on Windows if required by the packet capture environment

### 1. Clone the Repository

```bash
git clone https://github.com/sivabharathi0211/Live_network_packet_monitoring_dashboard.git
```

### 2. Navigate to the Project Directory

```bash
cd Live_network_packet_monitoring_dashboard
```

### 3. Create a Virtual Environment

```bash
python -m venv .venv
```

### 4. Activate the Virtual Environment

**Windows PowerShell:**

```powershell
.\.venv\Scripts\Activate.ps1
```

**Windows Command Prompt:**

```cmd
.venv\Scripts\activate
```

**Linux / macOS:**

```bash
source .venv/bin/activate
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the Application

```bash
python app.py
```

### 7. Open the Dashboard

Open your web browser and navigate to:

```text
http://127.0.0.1:5000
```


## ▶️ How to Use

1. Start the Flask application.
2. Open the dashboard in your web browser.
3. Select the appropriate network interface if necessary.
4. Click **Start** to begin packet monitoring.
5. Observe live packet information and network statistics.
6. Use the available filters to inspect specific traffic.
7. Review discovered network devices.
8. Click **Stop** to stop packet capture.


## 🪟 Windows Configuration

For Windows users:

- Install **Npcap** if packet capture is unavailable.
- Run the terminal as Administrator when required for packet capture or device discovery.
- Select an active network interface from the dashboard.
- If the selected interface does not capture traffic, try another available active interface.


## 🔐 Privacy and Security

Privacy is an important design consideration of this project.

- Captures packet metadata only.
- Does not display packet payload contents.
- Does not store packet payload contents.
- Operates through a local dashboard.
- Intended for authorized network monitoring and educational use.

The monitoring information is limited to the metadata necessary to observe and analyze network traffic.


## ⚠️ Responsible Use

This project is intended for:

- Educational purposes
- Cybersecurity learning
- Network monitoring
- Authorized network analysis
- Laboratory and controlled environments

**Only monitor networks and devices that you own or have explicit permission to monitor.**

Live packet capture and device discovery may require Administrator/root privileges depending on the operating system and network configuration.


## 🎓 Project Information

**Project Title:** Live Network Packet Monitoring Dashboard  
**Project Type:** Final-Year Academic Project  
**Domain:** Cybersecurity and Network Monitoring  
**Application:** Web-Based Network Monitoring  
**Backend:** Python and Flask  


## 👨‍💻 Author

Siva Bharathi R | Cyber Security Student
Developed as a final-year academic project focused on network monitoring, cybersecurity, packet analysis, and real-time traffic visualization.
