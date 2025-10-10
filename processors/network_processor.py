#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from datetime import datetime
from .base_processor import BaseFileProcessor


class NetworkProcessor(BaseFileProcessor):
    """Processeur pour les fichiers texte contenant la sortie de 'netstat', 'tcpvcon', 'arp -a', ou des enregistrements DNS."""

    def _parse_address(self, address_str: str):
        try:
            ip, port = address_str.rsplit(':', 1)
            return ip, int(port)
        except (ValueError, AttributeError):
            return address_str, None

    def _process_netstat_line(self, line: str, machine_name: str) -> dict:
        parts = re.split(r'\s+', line.strip())
        if len(parts) < 4: return None
        proto, local_addr, foreign_addr, state, *pid_parts = parts
        pid = pid_parts[0] if pid_parts else None
        local_ip, local_port = self._parse_address(local_addr)
        foreign_ip, foreign_port = self._parse_address(foreign_addr)
        return {"@timestamp": datetime.utcnow().isoformat() + "Z", "host": {"name": machine_name},
                "event": {"kind": "event", "category": "network", "dataset": "netstat", "original": line.strip()},
                "source": {"ip": local_ip, "port": local_port}, "destination": {"ip": foreign_ip, "port": foreign_port},
                "network": {"transport": proto.lower(), "state": state}, "process": {"pid": pid}}

    def _process_tcpvcon_line(self, line: str, machine_name: str) -> dict:
        parts = [p.strip() for p in line.strip().split(',')]
        if len(parts) < 6: return None
        proto, process_name, pid, state, local_addr, foreign_addr = parts
        local_ip, local_port = self._parse_address(local_addr)
        foreign_ip, foreign_port = self._parse_address(foreign_addr)
        return {"@timestamp": datetime.utcnow().isoformat() + "Z", "host": {"name": machine_name},
                "event": {"kind": "event", "category": "network", "dataset": "tcpvcon", "original": line.strip()},
                "source": {"ip": local_ip, "port": local_port}, "destination": {"ip": foreign_ip, "port": foreign_port},
                "network": {"transport": proto.lower(), "state": state}, "process": {"pid": pid, "name": process_name}}

    def _process_arp_line(self, line: str, machine_name: str, interface_ip: str) -> dict:
        parts = re.split(r'\s+', line.strip())
        if len(parts) < 3: return None
        ip_address, mac_address, arp_type = parts[0], parts[1], parts[2]
        return {"@timestamp": datetime.utcnow().isoformat() + "Z", "host": {"name": machine_name},
                "event": {"kind": "event", "category": "network", "dataset": "arp", "original": line.strip()},
                "source": {"ip": ip_address, "mac": mac_address.lower().replace('-', ':')},
                "network": {"type": arp_type.lower(), "interface": {"ip": interface_ip}}}

    def _parse_dns_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str or timestamp_str.strip() == '0':
            return datetime.utcnow().isoformat() + "Z"
        try:
            dt_object = datetime.strptime(timestamp_str.strip(), '%m/%d/%Y %I:%M:%S %p')
            return dt_object.isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _process_dns_line(self, line: str, zone: str, machine_name: str) -> dict:
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) != 6: return None
        hostname, record_type, _, timestamp, ttl, record_data = parts
        return {"@timestamp": self._parse_dns_timestamp(timestamp), "host": {"name": machine_name},
                "event": {"kind": "event", "category": "network", "dataset": "dns", "original": line.strip()},
                "dns": {"question": {"name": hostname, "type": record_type}, "zone": zone,
                        "answers": {"data": record_data, "ttl": ttl, "type": record_type}}}

    def process_file(self, filepath: str, **kwargs):
        machine_name = kwargs.get("machine_name")
        print(f"  -> Lecture du fichier Réseau (texte) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        content_sample = " ".join(lines[:5])
        file_format = "tcpvcon" if "Tcpvcon.exe" in content_sample else "netstat" if "Active Connections" in content_sample else "arp" if "Internet Address" in content_sample and "Physical Address" in content_sample else "dns" if "HostName" in content_sample and "RecordType" in content_sample else None
        if not file_format:
            print(f"  [Attention] Format de fichier réseau non reconnu pour {filepath}. Ignoré.")
            return

        print(f"    -> Format détecté : {file_format}")
        if file_format == "dns":
            current_zone = "unknown"
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('---') or line.lower().startswith('hostname'): continue
                if line.startswith('***'):
                    current_zone = line.strip().strip(' *')
                    continue
                try:
                    doc = self._process_dns_line(line, current_zone, machine_name)
                    if doc: yield doc, "network"
                except Exception as e:
                    print(f"\n[Attention] Impossible de traiter la ligne DNS #{line_num}. Erreur: {e}\n")
        elif file_format == "arp":
            current_interface = None
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.lower().startswith('internet address'): continue
                if line.lower().startswith('interface:'):
                    current_interface = line.split('---')[0].replace('Interface:', '').strip()
                    continue
                try:
                    if len(re.split(r'\s+', line)) >= 3:
                        doc = self._process_arp_line(line, machine_name, current_interface)
                        if doc: yield doc, "network"
                except Exception as e:
                    print(f"\n[Attention] Impossible de traiter la ligne ARP #{line_num}. Erreur: {e}\n")
        else:  # Logic for netstat and tcpvcon
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or not (line.lower().startswith('tcp') or line.lower().startswith('udp')): continue
                try:
                    doc = None
                    if file_format == "tcpvcon":
                        doc = self._process_tcpvcon_line(line, machine_name)
                    elif file_format == "netstat":
                        doc = self._process_netstat_line(line, machine_name)
                    if doc: yield doc, "network"
                except Exception as e:
                    print(f"\n[Attention] Impossible de traiter la ligne réseau #{line_num}. Erreur: {e}\n")
