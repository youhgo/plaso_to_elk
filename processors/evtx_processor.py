#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from datetime import datetime
from .base_processor import BaseFileProcessor


class EvtxHandler:
    """
    Contient la logique de parsing pour les différents Event ID des logs EVTX.
    """

    def __init__(self):
        self.EVENT_HANDLERS = {
            # Security
            4624: self.handle_security_logon, 4625: self.handle_security_logon_fail,
            4648: self.handle_security_logon, 4688: self.handle_security_process_created,
            4720: self.handle_user_modification, 4723: self.handle_user_modification,
            4724: self.handle_user_modification, 4726: self.handle_user_modification,
            # System
            7045: self.handle_system_service_install,
        }

    def _get_system_data(self, raw_log: dict) -> dict:
        return raw_log.get("Event", {}).get("System", {})

    def _get_event_data(self, raw_log: dict) -> dict:
        return raw_log.get("Event", {}).get("EventData", {})

    def _format_timestamp(self, time_str: str) -> str:
        if not time_str: return datetime.utcnow().isoformat() + "Z"
        if '.' in time_str and len(time_str.split('.')[1]) > 7: time_str = time_str[:-2] + 'Z'
        try:
            return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%f%z").isoformat()
        except ValueError:
            return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ").isoformat()

    def _create_base_document(self, raw_log: dict) -> dict:
        system_data = self._get_system_data(raw_log)
        time_created = system_data.get("TimeCreated", {}).get("SystemTime")
        event_id_value = system_data.get("EventID", 0)
        final_event_id = int(event_id_value.get("#text", 0)) if isinstance(event_id_value, dict) else int(
            event_id_value)
        return {"@timestamp": self._format_timestamp(time_created), "host": {"name": system_data.get("Computer")},
                "winlog": {"provider_name": system_data.get("Provider", {}).get("Name"), "event_id": final_event_id,
                           "channel": system_data.get("Channel")},
                "event": {"kind": "event", "category": "host", "original": json.dumps(raw_log)}}

    def handle_generic(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        doc["winlog"]["event_data_str"] = json.dumps(self._get_event_data(raw_log))
        return doc

    def handle_security_logon(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        try:
            port = int(data.get("IpPort")) if data.get("IpPort") not in ["-", "0"] else None
        except (ValueError, TypeError):
            port = None
        doc.update({"event": {**doc["event"], "action": "logon", "type": "start", "outcome": "success"},
                    "source": {"user": {"name": data.get("SubjectUserName")},
                               "ip": data.get("IpAddress") if data.get("IpAddress") != "-" else None, "port": port},
                    "user": {"name": data.get("TargetUserName"), "domain": data.get("TargetDomainName")},
                    "winlog": {**doc["winlog"], "logon": {"type": data.get("LogonType")}}})
        return doc

    def handle_security_logon_fail(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        failure_reasons = {"0xc000006a": "Incorrect password", "0xc0000072": "Account disabled"}
        status_code = data.get("Status", "").lower()
        failure_text = failure_reasons.get(status_code, status_code)
        try:
            port = int(data.get("IpPort")) if data.get("IpPort") not in ["-", "0"] else None
        except (ValueError, TypeError):
            port = None
        doc.update({"event": {**doc["event"], "action": "logon", "type": "start", "outcome": "failure"},
                    "source": {"user": {"name": data.get("SubjectUserName")},
                               "ip": data.get("IpAddress") if data.get("IpAddress") != "-" else None, "port": port},
                    "user": {"name": data.get("TargetUserName")},
                    "winlog": {**doc["winlog"], "logon": {"type": data.get("LogonType")}},
                    "error": {"code": status_code, "message": failure_text}})
        return doc

    def handle_security_process_created(self, raw_log: dict) -> dict:
        doc, data = self._create_base_document(raw_log), self._get_event_data(raw_log)
        try:
            pid = int(data.get('ProcessId', '0x0'), 16)
        except (ValueError, TypeError):
            pid = 0
        try:
            parent_pid = int(data.get('CreatorProcessId', '0x0'), 16)
        except (ValueError, TypeError):
            parent_pid = 0
        doc.update({"event": {**doc["event"], "action": "process_started", "type": "start"},
                    "process": {"executable": data.get("NewProcessName"),
                                "name": os.path.basename(data.get("NewProcessName", "")), "pid": pid,
                                "command_line": data.get("CommandLine"), "parent": {"pid": parent_pid}}})
        return doc

    def handle_user_modification(self, raw_log: dict) -> dict:
        doc, data = self._create_base_document(raw_log), self._get_event_data(raw_log)
        actions = {4720: "user_created", 4726: "user_deleted", 4723: "password_changed", 4724: "password_reset"}
        doc.update({"event": {**doc["event"], "action": actions.get(doc["winlog"]["event_id"], "user_modified")},
                    "user": {"name": data.get("TargetUserName"), "id": data.get("TargetSid")},
                    "source_user": {"name": data.get("SubjectUserName")}})
        return doc

    def handle_system_service_install(self, raw_log: dict) -> dict:
        doc, data = self._create_base_document(raw_log), self._get_event_data(raw_log)
        doc.update({"event": {**doc["event"], "action": "service_installed"},
                    "service": {"name": data.get("ServiceName"), "path": data.get("ImagePath"),
                                "start_type": data.get("StartType"), "account": data.get("AccountName")}})
        return doc


class EvtxJsonProcessor(BaseFileProcessor):
    """Processeur pour les fichiers EVTX (format JSON Lines)."""

    def __init__(self):
        self.handler = EvtxHandler()

    def _process_log(self, raw_log: dict) -> dict:
        event_id_value = raw_log.get("Event", {}).get("System", {}).get("EventID", 0)
        try:
            event_id = int(event_id_value.get("#text", 0)) if isinstance(event_id_value, dict) else int(event_id_value)
        except (ValueError, TypeError):
            event_id = 0
        handler_method = self.handler.EVENT_HANDLERS.get(event_id, self.handler.handle_generic)
        return handler_method(raw_log)

    def process_file(self, filepath: str, **kwargs):
        print(f"  -> Lecture du fichier EVTX (JSON Lines) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                stripped_line = line.strip()
                if not stripped_line: continue
                try:
                    raw_log_data = json.loads(stripped_line)
                    if "Event" in raw_log_data:
                        yield self._process_log(raw_log_data), "evtx"
                except Exception as e:
                    print(
                        f"\n[Attention] Impossible de traiter la ligne {line_num} du fichier {filepath}. Erreur: {e}\nLigne: {stripped_line}\n")
