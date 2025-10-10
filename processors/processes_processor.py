#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import os
import xmltodict
import json
import re
from datetime import datetime
from .base_processor import BaseFileProcessor


class ProcessesProcessor(BaseFileProcessor):
    """Processeur pour divers formats de listes de processus et d'autoruns (CSV et XML)."""

    def _parse_wmi_timestamp(self, ts: str) -> str:
        if not ts or '.' not in ts: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.strptime(ts.split('.')[0], "%Y%m%d%H%M%S").isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _parse_ps_timestamp(self, ts: str) -> str:
        if not ts: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p").isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _parse_timeline_timestamp(self, ts: str) -> str:
        if not ts or ts.startswith("1601-01-01"): return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.strptime(ts.split('.')[0], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _parse_autoruns_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.strptime(timestamp_str, "%Y%m%d-%H%M%S").isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _process_win32_process_row(self, row: dict) -> dict:
        return {"@timestamp": self._parse_wmi_timestamp(row.get("CreationDate")),
                "host": {"name": row.get("PSComputerName")},
                "event": {"kind": "event", "category": "process", "dataset": "processes.win32_process",
                          "original": ",".join(str(v) for v in row.values())},
                "process": {"name": row.get("ProcessName"), "executable": row.get("ExecutablePath"),
                            "pid": row.get("ProcessId"), "parent": {"pid": row.get("ParentProcessId")},
                            "command_line": row.get("CommandLine")}}

    def _process_get_process_row(self, row: dict) -> dict:
        return {"@timestamp": self._parse_ps_timestamp(row.get("StartTime")), "host": {"name": row.get("MachineName")},
                "event": {"kind": "event", "category": "process", "dataset": "processes.get_process",
                          "original": ",".join(str(v) for v in row.values())},
                "process": {"name": row.get("ProcessName"), "executable": row.get("Path"), "pid": row.get("Id"),
                            "session_id": row.get("SI")}}

    def _process_sampleinfo_row(self, row: dict) -> dict:
        return {"@timestamp": datetime.utcnow().isoformat() + "Z", "host": {"name": row.get("ComputerName")},
                "event": {"kind": "event", "category": "process", "dataset": "processes.sampleinfo",
                          "original": ",".join(str(v) for v in row.values())},
                "file": {"path": row.get("FullPath"), "name": row.get("FileName")},
                "process": {"code_signature": {"status": row.get("Authenticode")}}, "status": row.get("Running")}

    def _process_timeline_row(self, row: dict) -> dict:
        return {"@timestamp": self._parse_timeline_timestamp(row.get("Time")),
                "host": {"name": row.get("ComputerName")},
                "event": {"kind": "event", "category": "process", "dataset": "processes.timeline",
                          "action": row.get("Type"), "original": ",".join(str(v) for v in row.values())},
                "process": {"pid": row.get("ProcessID"), "parent": {"pid": row.get("ParentID")}},
                "dll": {"path": row.get("FullPath")}}

    def _process_autoruns_csv_row(self, row: dict) -> dict:
        # Renommer les clés pour éviter les espaces, au cas où.
        processed_row = {k.replace(' ', ''): v for k, v in row.items() if k}
        return {
            "@timestamp": self._parse_autoruns_timestamp(processed_row.get("Time")),
            "event": {"kind": "event", "category": "process", "dataset": "autoruns",
                      "original": ",".join(str(v) for v in row.values())},
            "rule": {"name": processed_row.get("Entry"), "category": processed_row.get("Category")},
            "registry": {"path": processed_row.get("EntryLocation")},
            "process": {"executable": processed_row.get("ImagePath"),
                        "name": os.path.basename(processed_row.get("ImagePath")) if processed_row.get(
                            "ImagePath") else None, "version": processed_row.get("Version"),
                        "hash": {"md5": processed_row.get("MD5"), "sha1": processed_row.get("SHA-1"),
                                 "sha256": processed_row.get("SHA-256")},
                        "code_signature": {"subject_name": processed_row.get("Signer"),
                                           "publisher": processed_row.get("Company")}},
            "service": {"description": processed_row.get("Description")},
            "user": {"name": processed_row.get("Profile")},
            "status": processed_row.get("Enabled")
        }

    def _process_autoruns_xml_item(self, item: dict) -> dict:
        return {
            "@timestamp": self._parse_autoruns_timestamp(item.get("time")),
            "event": {"kind": "event", "category": "process", "dataset": "autoruns", "original": json.dumps(item)},
            "rule": {"name": item.get("itemname"), "category": item.get("category")},
            "registry": {"path": item.get("location")},
            "process": {"executable": item.get("imagepath"),
                        "name": os.path.basename(item.get("imagepath")) if item.get("imagepath") else None,
                        "version": item.get("version"),
                        "hash": {"md5": item.get("md5hash"), "sha1": item.get("sha1hash"),
                                 "sha256": item.get("sha256hash")},
                        "code_signature": {"subject_name": item.get("signer"), "publisher": item.get("company")}},
            "service": {"description": item.get("description")},
            "user": {"name": item.get("profile")},
            "status": item.get("enabled")
        }

    def _process_csv_data(self, lines: list, filepath: str):
        """Helper function to process a list of decoded CSV lines."""
        header_fields = None
        header_index = -1

        for i, line in enumerate(lines):
            clean_line = line.strip()
            if not clean_line or "Sysinternals" in clean_line or "Copyright" in clean_line:
                continue

            if "," in clean_line:
                try:
                    header_fields = next(csv.reader([clean_line]))
                    header_index = i
                    break
                except StopIteration:
                    continue

        if not header_fields:
            print(f"  [Attention] En-tête CSV non trouvé ou non reconnu pour {filepath}. Fichier ignoré.")
            return

        header_set = set(header_fields)
        parser_func, fmt = (None, None)

        if "PSComputerName" in header_set and "CreationDate" in header_set:
            parser_func, fmt = self._process_win32_process_row, "Win32_Process"
        elif "ProductVersion" in header_set and "PagedMemorySize64" in header_set:
            parser_func, fmt = self._process_get_process_row, "Get-Process *"
        elif "Authenticode" in header_set and "FullPath" in header_set:
            parser_func, fmt = self._process_sampleinfo_row, "SampleInfo"
        elif "ParentID" in header_set and "ProcessID" in header_set:
            parser_func, fmt = self._process_timeline_row, "Timeline"
        elif "Entry Location" in header_set and "Image Path" in header_set:
            parser_func, fmt = self._process_autoruns_csv_row, "Autoruns CSV"

        if not parser_func:
            print(f"  [Attention] Format de CSV de processus non reconnu pour {filepath}. Fichier ignoré.")
            return

        print(f"    -> Format détecté : {fmt}")

        csv_content = lines[header_index + 1:]
        reader = csv.DictReader(csv_content, fieldnames=header_fields)
        for i, row in enumerate(reader):
            try:
                if not any(row.values()): continue
                yield parser_func(row), "processes"
            except Exception as e:
                print(
                    f"\n[Attention] Impossible de traiter la ligne de processus #{i + header_index + 2}. Erreur: {e}\n")

    def process_file(self, filepath: str, **kwargs):
        print(f"  -> Lecture du fichier de Processus : {filepath}")
        file_extension = os.path.splitext(filepath)[1].lower()

        if file_extension == '.csv':
            lines = None
            try:
                # Try UTF-16 first, as it's common for tools like Autoruns
                with open(filepath, 'r', encoding='utf-16', errors='strict') as f:
                    lines = f.readlines()
                print("    -> Fichier lu avec l'encodage UTF-16.")
            except UnicodeError:
                # Fallback to UTF-8 for other CSVs
                print("    -> L'encodage UTF-16 a échoué, tentative avec UTF-8-SIG...")
                with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as f:
                    lines = f.readlines()
                print("    -> Fichier lu avec l'encodage UTF-8-SIG.")
            except Exception as e:
                print(f"  [ERREUR] Impossible de lire le fichier {filepath}. Erreur: {e}")
                return

            if lines:
                yield from self._process_csv_data(lines, filepath)

        elif file_extension == '.xml':
            print("    -> Format détecté : Autoruns XML")
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                try:
                    xml_content = f.read()
                    xml_content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', xml_content)
                    data = xmltodict.parse(xml_content)
                    items = data.get('autoruns', {}).get('item', [])
                    if not isinstance(items, list): items = [items]
                    for i, item in enumerate(items):
                        try:
                            yield self._process_autoruns_xml_item(item), "processes"
                        except Exception as e:
                            print(f"\n[Attention] Impossible de traiter l'item XML #{i + 1}. Erreur: {e}\n")
                except Exception as e:
                    print(f"[ERREUR] Impossible de parser le fichier XML {filepath}. Erreur: {e}")

