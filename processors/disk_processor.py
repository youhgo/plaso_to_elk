#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import csv
import os
from datetime import datetime
from .base_processor import BaseFileProcessor


class DiskProcessor(BaseFileProcessor):
    """Processeur pour les artefacts disque : MFT (JSON) et USN Journal (CSV)."""

    # --- Méthodes pour MFT ---
    def _get_valid_mft_timestamp(self, raw_log: dict) -> str:
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

    def _process_mft_log(self, raw_log: dict) -> dict:
        final_timestamp = self._get_valid_mft_timestamp(raw_log)
        for key in ["raw_record", "data_attribute", "data"]: raw_log.pop(key, None)
        return {"@timestamp": final_timestamp,
                "event": {"kind": "event", "category": "file", "dataset": "mft", "original": json.dumps(raw_log)},
                "file": {"name": raw_log.get("filename"), "size": raw_log.get("filesize"),
                         "record_number": raw_log.get("recordnum"), "parent_reference": raw_log.get("parent_ref"),
                         "timestamps": {"si": raw_log.get("si_times"), "fn": raw_log.get("fn_times")},
                         "flags": raw_log.get("flags")}}

    def _process_mft_file(self, filepath: str):
        print(f"  -> Lecture du fichier MFT (JSON complet) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                all_data = json.load(f)
                records = all_data if isinstance(all_data, list) else [all_data]
                for i, record in enumerate(records):
                    try:
                        if "recordnum" in record and "si_times" in record:
                            yield self._process_mft_log(record), "disk"
                    except Exception as e:
                        print(
                            f"\n[Attention] Impossible de traiter l'enregistrement MFT #{i + 1} du fichier {filepath}. Erreur: {e}\n")
            except json.JSONDecodeError as e:
                print(f"[ERREUR] Le fichier {filepath} n'est pas un JSON valide. Erreur: {e}")

    # --- Méthodes pour USN Journal ---
    def _parse_usn_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00").replace(" ", "T")).isoformat() + "Z"
        except ValueError:
            try:
                return datetime.strptime(timestamp_str.split('.')[0], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
            except ValueError:
                return datetime.utcnow().isoformat() + "Z"

    def _process_usn_row(self, row: dict) -> dict:
        original_line = ",".join(str(v) for v in row.values())
        return {"@timestamp": self._parse_usn_timestamp(row.get("TimeStamp")),
                "host": {"name": row.get("ComputerName")},
                "event": {"kind": "event", "category": "file", "dataset": "usnjrnl", "action": row.get("Reason"),
                          "original": original_line},
                "file": {"name": row.get("File"), "path": row.get("FullPath"), "attributes": row.get("FileAttributes")},
                "usn": {"usn": row.get("USN"), "frn": row.get("FRN"), "parent_frn": row.get("ParentFRN")},
                "volume": {"id": row.get("VolumeID")}}

    def _process_usn_file(self, filepath: str):
        print(f"  -> Lecture du fichier USN Journal (CSV) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                try:
                    yield self._process_usn_row(row), "disk"
                except Exception as e:
                    print(
                        f"\n[Attention] Impossible de traiter la ligne CSV #{i + 2} du fichier {filepath}. Erreur: {e}\n")

    # --- Méthode principale ---
    def process_file(self, filepath: str, **kwargs):
        """Détecte le type de fichier disque et appelle le bon processeur."""
        _, extension = os.path.splitext(filepath)
        if extension.lower() == '.json':
            yield from self._process_mft_file(filepath)
        elif extension.lower() == '.csv':
            yield from self._process_usn_file(filepath)
        else:
            print(f"  [Attention] Extension de fichier disque non reconnue pour '{filepath}'. Ignoré.")
