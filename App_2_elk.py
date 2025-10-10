#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import argparse
import csv
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import streaming_bulk


# ############################################################################
# Section des Handlers EVTX
# ############################################################################

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


# ############################################################################
# Section des Processeurs d'Artefacts
# ############################################################################

class BaseFileProcessor:
    """Classe de base abstraite pour tous les processeurs de fichiers."""

    def process_file(self, filepath: str):
        raise NotImplementedError


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

    def process_file(self, filepath: str):
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


class MftJsonProcessor(BaseFileProcessor):
    """Processeur pour les fichiers MFT (format JSON complet)."""

    def _get_valid_timestamp(self, raw_log: dict) -> str:
        for block, time_type in [('si_times', 'mtime'), ('si_times', 'crtime'), ('fn_times', 'mtime'),
                                 ('fn_times', 'crtime')]:
            timestamp_str = raw_log.get(block, {}).get(time_type)
            if timestamp_str:
                try:
                    datetime.strptime(timestamp_str.split('.')[0], "%Y-%m-%dT%H:%M:%S")
                    return timestamp_str
                except (ValueError, TypeError):
                    continue
        return datetime.utcnow().isoformat() + "Z"

    def _process_log(self, raw_log: dict) -> dict:
        final_timestamp = self._get_valid_timestamp(raw_log)
        for key in ["raw_record", "data_attribute", "data"]: raw_log.pop(key, None)
        return {"@timestamp": final_timestamp,
                "event": {"kind": "event", "category": "file", "dataset": "mft", "original": json.dumps(raw_log)},
                "file": {"name": raw_log.get("filename"), "size": raw_log.get("filesize"),
                         "record_number": raw_log.get("recordnum"), "parent_reference": raw_log.get("parent_ref"),
                         "timestamps": {"si": raw_log.get("si_times"), "fn": raw_log.get("fn_times")},
                         "flags": raw_log.get("flags")}}

    def process_file(self, filepath: str):
        print(f"  -> Lecture du fichier MFT (JSON complet) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                all_data = json.load(f)
                records = all_data if isinstance(all_data, list) else [all_data]
                for i, record in enumerate(records):
                    try:
                        if "recordnum" in record and "si_times" in record:
                            yield self._process_log(record), "mft"
                    except Exception as e:
                        print(
                            f"\n[Attention] Impossible de traiter l'enregistrement MFT #{i + 1} du fichier {filepath}. Erreur: {e}\n")
            except json.JSONDecodeError as e:
                print(f"[ERREUR] Le fichier {filepath} n'est pas un JSON valide. Erreur: {e}")


class UsnCsvProcessor(BaseFileProcessor):
    """Processeur pour les fichiers USN Journal (format CSV)."""

    def _parse_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00").replace(" ", "T")).isoformat() + "Z"
        except ValueError:
            try:
                return datetime.strptime(timestamp_str.split('.')[0], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
            except ValueError:
                return datetime.utcnow().isoformat() + "Z"

    def _process_row(self, row: dict) -> dict:
        original_line = ",".join(str(v) for v in row.values())
        return {"@timestamp": self._parse_timestamp(row.get("TimeStamp")), "host": {"name": row.get("ComputerName")},
                "event": {"kind": "event", "category": "file", "dataset": "usnjrnl", "action": row.get("Reason"),
                          "original": original_line},
                "file": {"name": row.get("File"), "path": row.get("FullPath"), "attributes": row.get("FileAttributes")},
                "usn": {"usn": row.get("USN"), "frn": row.get("FRN"), "parent_frn": row.get("ParentFRN")},
                "volume": {"id": row.get("VolumeID")}}

    def process_file(self, filepath: str):
        print(f"  -> Lecture du fichier USN Journal (CSV) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                try:
                    yield self._process_row(row), "usnjrnl"
                except Exception as e:
                    print(
                        f"\n[Attention] Impossible de traiter la ligne CSV #{i + 2} du fichier {filepath}. Erreur: {e}\n")


class LnkJsonProcessor(BaseFileProcessor):
    """Processeur pour les fichiers LNK (format JSON complet)."""

    def _format_lnk_timestamp(self, time_str: str) -> str:
        if not time_str: return None
        try:
            return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
        except (ValueError, TypeError):
            try:
                return datetime.fromisoformat(time_str.replace("Z", "+00:00")).isoformat() + "Z"
            except (ValueError, TypeError):
                return None

    def _get_valid_timestamp(self, raw_log: dict) -> str:
        header = raw_log.get("header", {})
        for key in ["modified_time", "accessed_time", "creation_time"]:
            ts = self._format_lnk_timestamp(header.get(key))
            if ts: return ts
        return datetime.utcnow().isoformat() + "Z"

    def _process_log(self, raw_log: dict) -> dict:
        final_timestamp = self._get_valid_timestamp(raw_log)
        header, data, extra = raw_log.get("header", {}), raw_log.get("data", {}), raw_log.get("extra", {})
        target_path = extra.get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK", {}).get("target_unicode") or extra.get(
            "ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK", {}).get("target_ansi")
        return {"@timestamp": final_timestamp,
                "event": {"kind": "event", "category": "file", "dataset": "lnk", "original": json.dumps(raw_log)},
                "file": {"path": target_path, "size": header.get("file_size"),
                         "directory": data.get("working_directory"),
                         "lnk": {"description": data.get("description"), "icon_location": data.get("icon_location"),
                                 "flags": header.get("link_flags"),
                                 "creation_time": self._format_lnk_timestamp(header.get("creation_time")),
                                 "modified_time": self._format_lnk_timestamp(header.get("modified_time")),
                                 "accessed_time": self._format_lnk_timestamp(header.get("accessed_time"))}}}

    def process_file(self, filepath: str):
        print(f"  -> Lecture du fichier LNK (JSON complet) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                all_data = json.load(f)
                records = all_data if isinstance(all_data, list) else [all_data]
                for i, record in enumerate(records):
                    try:
                        if "header" in record and "extra" in record: yield self._process_log(record), "lnk"
                    except Exception as e:
                        print(
                            f"\n[Attention] Impossible de traiter l'enregistrement LNK #{i + 1} du fichier {filepath}. Erreur: {e}\n")
            except json.JSONDecodeError as e:
                print(f"[ERREUR] Le fichier {filepath} n'est pas un JSON valide. Erreur: {e}")


class AmcacheJsonProcessor(BaseFileProcessor):
    """Processeur pour les fichiers Amcache (format JSON Lines)."""

    def _parse_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.fromisoformat(timestamp_str).isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _process_log(self, raw_log: dict) -> dict:
        final_timestamp = self._parse_timestamp(raw_log.get("last_written_timestamp"))
        values_data = json.dumps(raw_log.get("values", {}))
        return {"@timestamp": final_timestamp, "event": {"kind": "event", "category": "registry", "dataset": "amcache",
                                                         "original": json.dumps(raw_log)},
                "registry": {"path": raw_log.get("path"), "key": raw_log.get("name"), "values_json": values_data}}

    def process_file(self, filepath: str):
        print(f"  -> Lecture du fichier Amcache (JSON Lines) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                stripped_line = line.strip()
                if not stripped_line: continue
                try:
                    raw_log_data = json.loads(stripped_line)
                    if "path" in raw_log_data and "last_written_timestamp" in raw_log_data:
                        yield self._process_log(raw_log_data), "amcache"
                except Exception as e:
                    print(
                        f"\n[Attention] Impossible de traiter la ligne Amcache #{line_num} du fichier {filepath}. Erreur: {e}\n")


class RegistryJsonProcessor(BaseFileProcessor):
    """Processeur pour les fichiers de clés de registre génériques (format JSON Lines)."""

    def _parse_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.fromisoformat(timestamp_str).isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _process_log(self, raw_log: dict) -> dict:
        final_timestamp = self._parse_timestamp(raw_log.get("last_written_timestamp"))
        values_data = json.dumps(raw_log.get("values", {}))
        return {"@timestamp": final_timestamp, "event": {"kind": "event", "category": "registry", "dataset": "registry",
                                                         "original": json.dumps(raw_log)},
                "registry": {"path": raw_log.get("path"), "key": raw_log.get("name"), "values_json": values_data}}

    def process_file(self, filepath: str):
        print(f"  -> Lecture du fichier de registre (JSON Lines) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                stripped_line = line.strip()
                if not stripped_line: continue
                try:
                    raw_log_data = json.loads(stripped_line)
                    if "path" in raw_log_data and "last_written_timestamp" in raw_log_data:
                        yield self._process_log(raw_log_data), "registry"
                except Exception as e:
                    print(
                        f"\n[Attention] Impossible de traiter la ligne de registre #{line_num} du fichier {filepath}. Erreur: {e}\n")


# ############################################################################
# Classe d'Envoi Elasticsearch
# ############################################################################

class ElasticUploader:
    def __init__(self, es_hosts: list, es_user: str, es_pass: str, verify_ssl: bool = True):
        try:
            es_options = {"basic_auth": (es_user, es_pass), "verify_certs": verify_ssl}
            if not verify_ssl:
                import warnings
                from urllib3.exceptions import InsecureRequestWarning
                warnings.filterwarnings('ignore', category=InsecureRequestWarning)
                es_options["ca_certs"] = False
            self.client = Elasticsearch(es_hosts, **es_options)
            if not self.client.ping(): raise ConnectionError("La connexion à Elasticsearch a échoué.")
            print("Connexion à Elasticsearch réussie.")
        except Exception as e:
            raise ConnectionError(f"Impossible d'initialiser le client Elasticsearch : {e}")

    def _create_index_template(self, template_name: str, index_pattern: str):
        template_body = {"index_patterns": [index_pattern], "priority": 300,
                         "template": {"settings": {"index.mapping.total_fields.limit": 2000}, "mappings": {
                             "properties": {
                                 "@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"}}}}}
        try:
            self.client.indices.put_index_template(name=template_name, index_patterns=template_body["index_patterns"],
                                                   priority=template_body["priority"],
                                                   template=template_body["template"])
            print(f"Template d'index '{template_name}' pour le pattern '{index_pattern}' créé/mis à jour.")
        except Exception as e:
            print(f"[Attention] Impossible de créer le template d'index '{template_name}'. Erreur: {e}")

    def setup_templates(self, **kwargs):
        for name, pattern in kwargs.items():
            self._create_index_template(f"forensic_{name}_template", pattern)

    def streaming_bulk_upload(self, actions_generator, chunk_size: int):
        print(f"\nEnvoi des documents en streaming par lots de {chunk_size}...")
        success_count, fail_count = 0, 0
        try:
            for ok, result in streaming_bulk(client=self.client, actions=actions_generator, chunk_size=chunk_size,
                                             raise_on_error=False, raise_on_exception=False):
                if ok:
                    success_count += 1
                else:
                    fail_count += 1
                    print(f"\n[ERREUR D'ENVOI] Document échoué : {json.dumps(result, indent=2)}")
            print("\nEnvoi terminé.")
            print(f"Documents envoyés avec succès : {success_count}")
            if fail_count > 0: print(f"Documents en échec : {fail_count}")
        except Exception as e:
            print(f"Une erreur critique est survenue durant l'envoi en streaming : {e}")


# ############################################################################
# Section Principale (Main)
# ############################################################################

def parse_arguments():
    parser = argparse.ArgumentParser(description="Processeur de logs forensiques pour envoi vers Elasticsearch.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-c", "--case-name", required=True, help="Nom du cas.")
    parser.add_argument("-m", "--machine-name", required=True, help="Nom de la machine analysée.")
    parser.add_argument("--evtx-files", nargs='+', help="Un ou plusieurs fichiers de logs EVTX (JSON Lines).")
    parser.add_argument("--mft-files", nargs='+', help="Un ou plusieurs fichiers MFT (JSON complet).")
    parser.add_argument("--usnjrnl-files", nargs='+', help="Un ou plusieurs fichiers USN Journal (CSV).")
    parser.add_argument("--lnk-files", nargs='+', help="Un ou plusieurs fichiers LNK (JSON complet).")
    parser.add_argument("--amcache-files", nargs='+', help="Un ou plusieurs fichiers Amcache (JSON Lines).")
    parser.add_argument("--registry-files", nargs='+', help="Un ou plusieurs fichiers de Registre (JSON Lines).")
    parser.add_argument("--es-hosts", default="https://localhost:9200",
                        help="Hôte(s) Elasticsearch, séparés par des virgules.")
    parser.add_argument("--es-user", default="elastic", help="Nom d'utilisateur pour Elasticsearch.")
    parser.add_argument("--es-pass", default="changeme", help="Mot de passe pour Elasticsearch.")
    parser.add_argument("--chunk-size", type=int, default=500, help="Nombre de documents à envoyer par lot.")
    parser.add_argument("--no-verify-ssl", action="store_false", dest="verify_ssl",
                        help="Désactive la vérification du certificat SSL.")
    return parser.parse_args()


def sanitize_for_index(name: str) -> str:
    return ''.join(c if c.isalnum() or c in '-_' else '_' for c in name).lower()


if __name__ == "__main__":
    args = parse_arguments()
    case_name, machine_name = sanitize_for_index(args.case_name), sanitize_for_index(args.machine_name)
    target_indices = {"evtx": f"{case_name}_{machine_name}_evtx", "mft": f"{case_name}_{machine_name}_mft",
                      "usnjrnl": f"{case_name}_{machine_name}_usnjrnl", "lnk": f"{case_name}_{machine_name}_lnk",
                      "amcache": f"{case_name}_{machine_name}_amcache",
                      "registry": f"{case_name}_{machine_name}_registry"}

    print("--- CONFIGURATION ---")
    for doc_type, index_name in target_indices.items(): print(f"Index {doc_type.upper():<10}: {index_name}")
    print("---------------------\n")

    try:
        uploader = ElasticUploader(es_hosts=args.es_hosts.split(','), es_user=args.es_user, es_pass=args.es_pass,
                                   verify_ssl=args.verify_ssl)
        template_patterns = {name: f"*_{machine_name}_{name}" for name in target_indices.keys()}
        uploader.setup_templates(**template_patterns)

        processors = {"evtx": EvtxJsonProcessor(), "mft": MftJsonProcessor(), "usnjrnl": UsnCsvProcessor(),
                      "lnk": LnkJsonProcessor(), "amcache": AmcacheJsonProcessor(), "registry": RegistryJsonProcessor()}


        def combined_actions_generator():
            file_args = {"evtx": args.evtx_files, "mft": args.mft_files, "usnjrnl": args.usnjrnl_files,
                         "lnk": args.lnk_files, "amcache": args.amcache_files, "registry": args.registry_files}
            for file_type, file_list in file_args.items():
                if not file_list: continue

                processor = processors[file_type]
                for filepath in file_list:
                    if not os.path.exists(filepath):
                        print(f"[Attention] Le fichier '{filepath}' n'existe pas. Ignoré.")
                        continue
                    yield from ({"_index": target_indices[doc_type], "_source": doc} for doc, doc_type in
                                processor.process_file(filepath))


        uploader.streaming_bulk_upload(combined_actions_generator(), chunk_size=args.chunk_size)

    except (FileNotFoundError, ConnectionError) as e:
        print(f"\n[ERREUR] {e}")
    except Exception as e:
        import traceback

        print(f"\n[ERREUR INATTENDUE] Une erreur est survenue : {e}")
        traceback.print_exc()

