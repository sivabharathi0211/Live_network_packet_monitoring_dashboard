from collections import Counter, deque
from datetime import datetime
import socket
import threading

import psutil
from scapy.all import IP, IPv6, TCP, UDP, conf, get_if_list, sniff


SERVICE_PORTS = {80: "HTTP", 443: "HTTPS", 20: "FTP", 21: "FTP", 3306: "MySQL"}
PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


class PacketMonitor:
    def __init__(self, max_packets=1000):
        self.max_packets = max_packets
        self.packets = deque(maxlen=max_packets)
        self.lock = threading.Lock()
        self.capture_thread = None
        self.stop_event = threading.Event()
        self.running = False
        self.interface = None
        self.error = None
        self.local_ips = self._get_local_ips()

    def _get_local_ips(self):
        ips = set()
        for addresses in psutil.net_if_addrs().values():
            for address in addresses:
                if address.family in (socket.AF_INET, socket.AF_INET6):
                    ips.add(address.address.split("%")[0])
        ips.update({"127.0.0.1", "::1"})
        return ips

    def get_interfaces(self):
        scapy_interfaces = set(get_if_list())
        interfaces = []
        for name, stats in psutil.net_if_stats().items():
            interfaces.append({"name": name, "is_up": stats.isup, "speed_mbps": stats.speed, "available_for_capture": name in scapy_interfaces})
        return sorted(interfaces, key=lambda item: (not item["is_up"], item["name"].lower()))

    def start(self, interface=None):
        if self.running:
            return {"ok": False, "message": "Capture is already running."}
        self.local_ips = self._get_local_ips()
        self.stop_event.clear()
        self.error = None
        self.interface = interface or conf.iface
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.running = True
        self.capture_thread.start()
        return {"ok": True, "message": f"Packet capture started on {self.interface}.", "interface": str(self.interface)}

    def stop(self):
        if not self.running:
            return {"ok": True, "message": "Capture is already stopped."}
        self.stop_event.set()

        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        return {"ok": True, "message": "Packet capture stopped."}

    def get_status(self):
        return {"running": self.running, "interface": str(self.interface) if self.interface else None, "packet_count": len(self.packets), "error": self.error}

    def _capture_loop(self):
        try:
            sniff(iface=self.interface, prn=self._handle_packet, store=False, stop_filter=lambda _: self.stop_event.is_set())
        except PermissionError:
            self.error = "Permission denied. Run the app as Administrator/root for live capture."
        except Exception as exc:
            self.error = str(exc)
        finally:
            self.running = False

    def _handle_packet(self, packet):
        parsed = self._parse_packet(packet)
        if parsed:
            with self.lock:
                self.packets.appendleft(parsed)

    def _parse_packet(self, packet):
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if not ip_layer:
            return None
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = self._get_protocol_name(ip_layer)
        src_port = None
        dst_port = None
        if packet.haslayer(TCP):
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            protocol = "TCP"
        elif packet.haslayer(UDP):
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
            protocol = "UDP"
        return {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "source_ip": src_ip, "destination_ip": dst_ip, "protocol": protocol, "source_port": src_port, "destination_port": dst_port, "service": self._classify_service(src_port, dst_port), "size": len(packet), "direction": self._direction(src_ip, dst_ip)}

    def _get_protocol_name(self, ip_layer):
        proto = getattr(ip_layer, "proto", None) or getattr(ip_layer, "nh", None)
        return PROTOCOL_NAMES.get(proto, str(proto or "Unknown"))

    def _classify_service(self, src_port, dst_port):
        for port in (dst_port, src_port):
            if port in SERVICE_PORTS:
                return SERVICE_PORTS[port]
        return "Other"

    def _direction(self, src_ip, dst_ip):
        src_local = src_ip in self.local_ips
        dst_local = dst_ip in self.local_ips
        if src_local and not dst_local:
            return "Outgoing"
        if dst_local and not src_local:
            return "Incoming"
        if src_local and dst_local:
            return "Local"
        return "Transit/Other"

    def get_packets(self, filters=None, limit=300):
        filters = filters or {}
        try:
            limit = max(1, min(int(limit), self.max_packets))
        except ValueError:
            limit = 300
        
        with self.lock:
            packets = list(self.packets)
        return [packet for packet in packets if self._matches_filters(packet, filters)][:limit]

    def _matches_filters(self, packet, filters):
        ip_filter = filters.get("ip", "").lower()
        protocol_filter = filters.get("protocol", "").lower()
        port_filter = filters.get("port", "")
        service_filter = filters.get("service", "").lower()
        if ip_filter and ip_filter not in packet["source_ip"].lower() and ip_filter not in packet["destination_ip"].lower():
            return False
        if protocol_filter and protocol_filter != packet["protocol"].lower():
            return False
        if port_filter:
            if not port_filter.isdigit():
                return False
            port = int(port_filter)
            if port not in (packet["source_port"], packet["destination_port"]):
                return False
        if service_filter and service_filter != packet["service"].lower():
            return False
        return True

    def get_statistics(self):
        with self.lock:
            packets = list(self.packets)
        return {"total_packets": len(packets), "total_bytes": sum(packet["size"] for packet in packets), "services": dict(Counter(packet["service"] for packet in packets)), "protocols": dict(Counter(packet["protocol"] for packet in packets)), "directions": dict(Counter(packet["direction"] for packet in packets))}
