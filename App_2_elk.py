#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import traceback

from elastic_uploader import ElasticUploader
from processors.evtx_processor import EvtxJsonProcessor
from processors.disk_processor import DiskProcessor
from processors.lnk_processor import LnkJsonProcessor
from processors.registry_processor import RegistryJsonProcessor
from processors.network_processor import NetworkProcessor
from processors.processes_processor import ProcessesProcessor


def parse_arguments():
    """Définit et parse les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Processeur de logs forensiques pour envoi vers Elasticsearch.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-c", "--case-name", required=True, help="Nom du cas.")
    parser.add_argument("-m", "--machine-name", required=True, help="Nom de la machine analysée.")
    parser.add_argument("--evtx-files", nargs='+', help="Un ou plusieurs fichiers de logs EVTX (JSON Lines).")
    parser.add_argument("--disk-files", nargs='+', help="Un ou plusieurs fichiers disque (MFT JSON, USN Journal CSV).")
    parser.add_argument("--lnk-files", nargs='+', help="Un ou plusieurs fichiers LNK (JSON complet).")
    parser.add_argument("--registry-files", nargs='+',
                        help="Un ou plusieurs fichiers de Registre ou Amcache (JSON Lines).")
    parser.add_argument("--network-files", nargs='+',
                        help="Un ou plusieurs fichiers réseau (Netstat, Tcpvcon, Arp, DNS).")
    parser.add_argument("--processes-files", nargs='+',
                        help="Un ou plusieurs fichiers de processus/autoruns (CSV ou XML).")
    parser.add_argument("--es-hosts", default="https://localhost:9200",
                        help="Hôte(s) Elasticsearch, séparés par des virgules.")
    parser.add_argument("--es-user", default="elastic", help="Nom d'utilisateur pour Elasticsearch.")
    parser.add_argument("--es-pass", default="changeme", help="Mot de passe pour Elasticsearch.")
    parser.add_argument("--chunk-size", type=int, default=2000, help="Nombre de documents à envoyer par lot.")
    parser.add_argument("--no-verify-ssl", action="store_false", dest="verify_ssl",
                        help="Désactive la vérification du certificat SSL.")
    return parser.parse_args()


def sanitize_for_index(name: str) -> str:
    """Nettoie une chaîne pour qu'elle soit valide dans un nom d'index Elasticsearch."""
    return ''.join(c if c.isalnum() or c in '-_' else '_' for c in name).lower()


if __name__ == "__main__":
    args = parse_arguments()
    case_name, machine_name = sanitize_for_index(args.case_name), sanitize_for_index(args.machine_name)

    target_indices = {
        "evtx": f"{case_name}_{machine_name}_evtx",
        "disk": f"{case_name}_{machine_name}_disk",
        "lnk": f"{case_name}_{machine_name}_lnk",
        "registry": f"{case_name}_{machine_name}_registry",
        "network": f"{case_name}_{machine_name}_network",
        "processes": f"{case_name}_{machine_name}_processes"
    }

    print("--- CONFIGURATION ---")
    for doc_type, index_name in target_indices.items():
        print(f"Index {doc_type.upper():<10}: {index_name}")
    print("---------------------\n")

    try:
        uploader = ElasticUploader(es_hosts=args.es_hosts.split(','), es_user=args.es_user, es_pass=args.es_pass,
                                   verify_ssl=args.verify_ssl)

        template_patterns = {name: f"*_{machine_name}_{name}" for name in target_indices.keys()}
        uploader.setup_templates(**template_patterns)

        processors = {
            "evtx": EvtxJsonProcessor(), "disk": DiskProcessor(),
            "lnk": LnkJsonProcessor(), "registry": RegistryJsonProcessor(),
            "network": NetworkProcessor(), "processes": ProcessesProcessor()
        }


        def combined_actions_generator():
            """Générateur qui produit les actions pour tous les types de logs."""
            file_args = {
                "evtx": args.evtx_files, "disk": args.disk_files,
                "lnk": args.lnk_files, "registry": args.registry_files,
                "network": args.network_files, "processes": args.processes_files
            }
            for file_type, file_list in file_args.items():
                if not file_list:
                    continue

                processor = processors.get(file_type)
                if not processor:
                    continue

                for filepath in file_list:
                    if not os.path.exists(filepath):
                        print(f"[Attention] Le fichier '{filepath}' n'existe pas. Ignoré.")
                        continue

                    process_kwargs = {"machine_name": machine_name} if file_type in ["network"] else {}
                    yield from ({"_index": target_indices[doc_type], "_source": doc} for doc, doc_type in
                                processor.process_file(filepath, **process_kwargs))


        uploader.streaming_bulk_upload(combined_actions_generator(), chunk_size=args.chunk_size)

    except (FileNotFoundError, ConnectionError) as e:
        print(f"\n[ERREUR] {e}")
    except Exception as e:
        import traceback

        print(f"\n[ERREUR INATTENDUE] Une erreur est survenue : {e}")
        traceback.print_exc()

