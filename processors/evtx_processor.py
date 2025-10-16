#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from datetime import datetime
import os
import re
from .base_processor import BaseFileProcessor


class EvtxHandler:
    """
    Contient la logique de parsing pour les différents Event ID des logs EVTX.
    """

    def __init__(self):
        # Dispatcher pour les logs de Sécurité
        self.SECURITY_EVENT_HANDLERS = {
            4624: self.handle_security_logon,
            4625: self.handle_security_logon_fail,
            4648: self.handle_security_logon,
            4672: self.handle_4672_special_privileges,
            4688: self.handle_security_process_created,
            4720: self.handle_user_modification,
            4723: self.handle_user_modification,
            4724: self.handle_user_modification,
            4726: self.handle_user_modification
        }
        # Dispatcher pour les logs PowerShell
        self.POWERSHELL_EVENT_HANDLERS = {
            4103: self.handle_ps_module_logging,
            4104: self.handle_ps_script_block,
        }
        # Dispatcher pour les logs Système
        self.SYSTEM_EVENT_HANDLERS = {
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

        final_event_id = 0
        if isinstance(event_id_value, dict):
            id_val = event_id_value.get("Value") or event_id_value.get("#text")
            try:
                final_event_id = int(id_val)
            except (ValueError, TypeError):
                pass
        else:
            try:
                final_event_id = int(event_id_value)
            except (ValueError, TypeError):
                pass

        return {"@timestamp": self._format_timestamp(time_created), "host": {"name": system_data.get("Computer")},
                "winlog": {"provider_name": system_data.get("Provider", {}).get("Name"), "event_id": final_event_id,
                           "channel": system_data.get("Channel")},
                "event": {"kind": "event", "category": "host", "original": json.dumps(raw_log)}}

    def handle_generic_evtx(self, raw_log: dict) -> dict:
        """Handler générique pour les EventID non spécifiquement traités."""
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
        doc.update({"event": {**doc["event"],
                              "action": "service_installed"},
                    "service": {"name": data.get("ServiceName"),
                                "path": data.get("ImagePath"),
                                "start_type": data.get("StartType"),
                                "account": data.get("AccountName")}})
        return doc

    def handle_4672_special_privileges(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        doc.update({
            "event": {**doc["event"], "action": "special_privileges_assigned"},
            "user": {"name": data.get("SubjectUserName"), "domain": data.get("SubjectDomainName")},
            "winlog": {**doc["winlog"], "event_data": {"privileges": data.get("PrivilegeList")}}
        })
        return doc

    def handle_ps_script_block(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        doc.update({
            "event": {**doc["event"], "action": "powershell_script_block_execution"},
            "process": {"pid": data.get("HostId"), "name": data.get("HostName")},
            "powershell": {"script_block_id": data.get("ScriptBlockId"),
                           "script_block_text": data.get("ScriptBlockText"), "path": data.get("Path")}
        })
        return doc

    def handle_ps_module_logging(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        doc.update({
            "event": {**doc["event"], "action": "powershell_module_pipeline_execution"},
            "powershell": {"context": data.get("Context"), "payload": data.get("Payload")}
        })
        return doc


class EvtxJsonProcessor(BaseFileProcessor):
    """Processeur pour les fichiers EVTX (format JSON ou JSON Lines)."""

    def __init__(self):
        self.handler = EvtxHandler()
        self.LOG_TYPE_PROCESSORS = {
            'security': self._process_security_log,
            'system': self._process_system_log,
            'powershell_operational': self._process_powershell_log,
            'windows_powershell': self._process_powershell_log,
        }
        self.LOG_FILE_MAP = {
            r'(\d+_)?Security\.evtx\.json': "security",
            r'(\d+_)?System\.evtx\.json': "system",
            r'^Security\.evtx\.json': "security",
            r'^System\.evtx\.json': "system",
            r'.*Microsoft-Windows-TaskScheduler.*Operational\.evtx\.json': "taskScheduler",
            r'.*Microsoft-Windows-TerminalServices-RemoteConnectionManager.*Operational\.evtx\.json': "rdp_remote",
            r'.*Microsoft-Windows-TerminalServices-LocalSessionManager.*Operational\.evtx\.json': "rdp_local",
            r'.*Microsoft-Windows-Bits-Client.*Operational\.evtx\.json': "bits",
            r'.*Microsoft-Windows-PowerShell.*Operational\.evtx\.json': "powershell_operational",
            r'.*Windows PowerShell\.evtx\.json': "windows_powershell",
            r'.*Microsoft-Windows-WMI-Activity.*Operational\.evtx\.json': "wmi",
            r'.*Microsoft-Windows-Windows Defender.*Operational\.evtx\.json': "windefender",
        }

    def _get_event_id(self, raw_log: dict) -> int:
        event_id_value = raw_log.get("Event", {}).get("System", {}).get("EventID", 0)
        try:
            if isinstance(event_id_value, dict):
                id_val = event_id_value.get("Value") or event_id_value.get("#text")
                return int(id_val)
            else:
                return int(event_id_value)
        except (ValueError, TypeError):
            return 0

    def _process_security_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.SECURITY_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_powershell_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.POWERSHELL_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_system_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.SYSTEM_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_generic_evtx(self, raw_log: dict) -> dict:
        return self.handler.handle_generic_evtx(raw_log)

    def _yield_from_records(self, records: list, processor_method):
        """Helper to process a list of records."""
        for i, record in enumerate(records):
            try:
                if "Event" in record:
                    processed_log = processor_method(record)
                    yield processed_log, "evtx"
            except Exception as e:
                print(f"\n[Attention] Impossible de traiter l'enregistrement EVTX #{i + 1}. Erreur: {e}\n")

    def process_file(self, filepath: str, **kwargs):
        filename = os.path.basename(filepath)
        print(f"  -> Lecture du fichier EVTX : {filename}")

        processor_method = self._process_generic_evtx
        log_type = "generic"
        for pattern, type_name in self.LOG_FILE_MAP.items():
            if re.search(pattern, filename, re.IGNORECASE):
                log_type = type_name
                processor_method = self.LOG_TYPE_PROCESSORS.get(log_type, self._process_generic_evtx)
                break

        print(f"    -> Type de log détecté : {log_type}. Utilisation du processeur : {processor_method.__name__}")

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                # Essayer de lire comme un JSON complet d'abord
                all_data = json.load(f)
                records = all_data if isinstance(all_data, list) else [all_data]
                print(f"    -> Fichier détecté comme JSON complet.")
                yield from self._yield_from_records(records, processor_method)
            except json.JSONDecodeError:
                # Si ça échoue, on suppose que c'est du JSON Lines
                print(f"    -> Fichier détecté comme JSON Lines.")
                f.seek(0)
                for line_num, line in enumerate(f, 1):
                    stripped_line = line.strip()
                    if not stripped_line: continue
                    try:
                        raw_log_data = json.loads(stripped_line)
                        if "Event" in raw_log_data:
                            processed_log = processor_method(raw_log_data)
                            yield processed_log, "evtx"
                    except Exception as e:
                        print(
                            f"\n[Attention] Impossible de traiter la ligne {line_num}. Erreur: {e}\nLigne: {stripped_line}\n")

