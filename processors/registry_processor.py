#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from datetime import datetime
from .base_processor import BaseFileProcessor


class RegistryJsonProcessor(BaseFileProcessor):
    """Processeur pour les fichiers de registre (Amcache et clés génériques) au format JSON Lines."""

    def _parse_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.fromisoformat(timestamp_str).isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _process_log(self, raw_log: dict, dataset: str) -> dict:
        final_timestamp = self._parse_timestamp(raw_log.get("last_written_timestamp"))

        # Gère les clés de valeur vides "" en les renommant en "(Default)"
        # et s'assure que toutes les données sont des chaînes pour éviter les conflits de mapping.
        values_data = {}
        for k, v in raw_log.get("values", {}).items():
            key_name = "(Default)" if k == "" else k
            values_data[key_name] = str(v.get("data"))

        return {
            "@timestamp": final_timestamp,
            "event": {"kind": "event", "category": "registry", "dataset": dataset, "original": json.dumps(raw_log)},
            "registry": {"path": raw_log.get("path"), "key": raw_log.get("name"), "values": values_data}
        }

    def process_file(self, filepath: str, **kwargs):
        print(f"  -> Lecture du fichier de registre (JSON Lines) : {filepath}")

        # Détermine le type de dataset en fonction du nom de fichier
        dataset = "amcache" if "amcache" in os.path.basename(filepath).lower() else "registry"
        print(f"    -> Dataset détecté : {dataset}")

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                stripped_line = line.strip()
                if not stripped_line: continue
                try:
                    raw_log_data = json.loads(stripped_line)
                    if "path" in raw_log_data and "last_written_timestamp" in raw_log_data:
                        yield self._process_log(raw_log_data,
                                                dataset), "registry"  # Envoie toujours vers l'index 'registry'
                except Exception as e:
                    print(
                        f"\n[Attention] Impossible de traiter la ligne de registre #{line_num} du fichier {filepath}. Erreur: {e}\n")

