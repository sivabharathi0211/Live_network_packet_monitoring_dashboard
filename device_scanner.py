import ipaddress
import socket
import subprocess
import time

import psutil
from scapy.all import ARP, Ether, srp


class DeviceScanner:
    def __init__(self, cache_seconds=60):
        self.cache_seconds = cache_seconds
        self.last_scan = 0
        self.cached_devices = []

    def get_devices(self, refresh=False):
        now = time.time()
        if not refresh and self.cached_devices and now - self.last_scan < self.cache_seconds:
            return self.cached_devices
        devices = self._scan_with_arp()
        if not devices:
            devices = self._read_arp_cache()
        self.cached_devices = sorted(devices, key=lambda item: self._ip_sort_key(item["ip"]))
        self.last_scan = now
        return self.cached_devices

    def _scan_with_arp(self):
        networks = self._local_ipv4_networks()
        devices = {}
        for network in networks:
            try:
                request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
                answers = srp(request, timeout=2, verbose=False)[0]
            except PermissionError:
                return []
            except Exception:
                continue
            for _, response in answers:
                ip = response.psrc
                devices[ip] = {"ip": ip, "mac": response.hwsrc, "hostname": self._resolve_hostname(ip), "source": "ARP scan"}
        return list(devices.values())

    def _local_ipv4_networks(self):
        networks = []
        for addresses in psutil.net_if_addrs().values():
            for address in addresses:
                if address.family != socket.AF_INET:
                    continue
                if not address.netmask or address.address.startswith("127."):
                    continue
                try:
                    interface = ipaddress.ip_interface(f"{address.address}/{address.netmask}")
                    if interface.network.num_addresses <= 4096:
                        networks.append(interface.network)
                except ValueError:
                    continue
        return networks

    def _read_arp_cache(self):
        try:
            completed = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=False, timeout=5)
        except Exception:
            return []
        devices = []
        seen = set()
        for line in completed.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            ip = parts[0].strip("()")
            mac = parts[1].replace("-", ":").lower()
            if not self._looks_like_ipv4(ip) or ip in seen:
                continue
            if mac in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
                continue
            seen.add(ip)
            devices.append({"ip": ip, "mac": mac, "hostname": self._resolve_hostname(ip), "source": "ARP cache"})
        return devices

    def _resolve_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"

    def _looks_like_ipv4(self, value):
        try:
            ipaddress.ip_address(value)
            return "." in value
        except ValueError:
            return False

    def _ip_sort_key(self, value):
        try:
            return int(ipaddress.ip_address(value))
        except ValueError:
            return 0
