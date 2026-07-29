# Live Network Packet Monitoring Dashboard

A Python Flask final-year project for authorized local network monitoring. It captures packet metadata only and displays live traffic, connected devices, service categories, statistics, filters, and capture controls.

## Features

- Live incoming and outgoing packet capture.
- Packet table with source IP, destination IP, protocol, source port, destination port, packet size, timestamp, direction, and service type.
- Connected device discovery with IP address, MAC address, and hostname/device name.
- Traffic classification into HTTP, HTTPS, FTP, MySQL, and Other.
- Filters for IP address, protocol, port, and service type.
- Start and stop capture buttons in the dashboard.
- No packet payload display or storage.
- Local-only Flask dashboard at 127.0.0.1.

## Important Use Notice

Use this project only on networks you own or have explicit permission to monitor. The dashboard intentionally records packet metadata only, not packet payloads or sensitive content.

Live packet capture and ARP scanning usually require Administrator/root permissions.

## How to Run

1. Open a terminal in this project folder.
2. Create a virtual environment: python -m venv .venv
3. Activate it on Windows PowerShell: .\.venv\Scripts\Activate.ps1
4. Install dependencies: pip install -r requirements.txt
5. Run the app: python app.py
6. Open: http://127.0.0.1:5000
7. Choose a network interface if needed, then click Start.

On macOS/Linux, activate with source .venv/bin/activate and use sudo python app.py if packet capture needs root permission.

## Windows Notes

- Install Npcap if Scapy cannot capture packets on Windows.
- Start PowerShell as Administrator for live capture and device discovery.
- If a selected interface does not capture traffic, use the default interface or try another active interface from the dropdown.

## Service Classification

- HTTP: 80
- HTTPS: 443
- FTP: 20 and 21
- MySQL: 3306
- Other: all remaining traffic

## Privacy Design

This project does not display or save packet payloads. Captured records contain only metadata required for monitoring and reporting.
