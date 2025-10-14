#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os
import argparse
import traceback
from elastic_uploader import ElasticUploader
from elastic_uploader import ElasticUploader
from processors.evtx_processor import EvtxJsonProcessor
from processors.disk_processor import DiskProcessor
from processors.lnk_processor import LnkJsonProcessor
from processors.registry_processor import RegistryJsonProcessor
from processors.network_processor import NetworkProcessor
from processors.processes_processor import ProcessesProcessor


def find_and_process_files(source_dir, processors, artefact_patterns, target_indices, machine_name):
    """
    Parcourt le répertoire source, identifie les fichiers via les patterns regex,
    et génère les actions pour l'envoi vers Elasticsearch.
    """
    print(f"[*] Recherche récursive des artefacts dans : {source_dir}")
    for root, _, files in os.walk(source_dir):
        for filename in files:
            dataset = None
            # Cherche une correspondance avec les patterns regex
            for pattern, ds in artefact_patterns.items():
                if re.match(pattern, filename, re.IGNORECASE):
                    dataset = ds
                    break

            if dataset:
                filepath = os.path.join(root, filename)
                print(f"  -> Fichier trouvé : {filepath} (dataset: {dataset})")

                # Détermine le processeur et la clé d'index à utiliser
                if dataset.startswith("registry") or dataset.startswith("amcache"):
                    processor_key = "registry"
                elif dataset in ["mft", "usnjrnl"]:
                    processor_key = "disk"
                elif dataset in ["netstat", "tcpvcon", "arp", "dns"]:
                    processor_key = "network"
                elif dataset.startswith("processes") or dataset.startswith("autoruns"):
                    processor_key = "processes"
                else:
                    processor_key = dataset  # Pour evtx, lnk

                processor = processors.get(processor_key)
                if not processor:
                    print(f"  [Attention] Aucun processeur trouvé pour le dataset '{dataset}'. Fichier ignoré.")
                    continue

                # Construction des arguments pour le processeur
                process_kwargs = {
                    "dataset": dataset,
                    "filename": filename
                }
                if processor_key == "network":
                    process_kwargs["machine_name"] = machine_name

                # Utilise le générateur du processeur pour créer les actions
                for doc, _ in processor.process_file(filepath, **process_kwargs):
                    yield {"_index": target_indices[processor_key], "_source": doc}


def parse_arguments():
    """Définit et parse les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Processeur de logs forensiques pour envoi vers Elasticsearch.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-c", "--case-name", required=True, help="Nom du cas.")
    parser.add_argument("-m", "--machine-name", required=True, help="Nom de la machine analysée.")
    parser.add_argument("-s", "--source-dir", required=True,
                        help="Répertoire source à scanner récursivement pour trouver les artefacts.")

    # Arguments pour la connexion Elasticsearch
    parser.add_argument("--es-hosts", default="https://localhost:9200",
                        help="Hôte(s) Elasticsearch, séparés par des virgules.")
    parser.add_argument("--es-user", default="elastic", help="Nom d'utilisateur pour Elasticsearch.")
    parser.add_argument("--es-pass", default="changeme", help="Mot de passe pour Elasticsearch.")
    parser.add_argument("--chunk-size", type=int, default=15000, help="Nombre de documents à envoyer par lot.")
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

    ARTEFACT_PATTERNS = {
        r'Amcache\.hve_regpy\.json': "amcache_regpy",
        r'Amcache\.hve_yarp\.jsonl': "amcache_yarp",
        r'SECURITY_yarp\.jsonl': "registry_security",
        r'SOFTWARE_yarp\.jsonl': "registry_software",
        r'SYSTEM_yarp\.jsonl': "registry_system",
        r'NTUSER\.DAT_yarp\.jsonl': "registry_ntuser",
        r'Security\.jsonl': "evtx",
        r'System\.jsonl': "evtx",
        r'mft\.json': "mft",
        r'USN.*\.csv': "usnjrnl",
        r'lnk_files\.json': "lnk",
        r'netstat\.txt': "netstat",
        r'tcpvcon\.txt': "tcpvcon",
        r'arp_cache\.txt': "arp",
        r'DNS_records\.txt': "dns",
        r'autoruns\.csv': "autoruns_sysinternals",
        r'processes1\.csv': "processes_win32",
        r'processes2\.csv': "processes_get_proc",
        r'Process_sampleinfo\.csv': "processes_sampleinfo",
        r'Process_timeline\.csv': "processes_timeline",
        r'Process_Autoruns\.xml': "processes_autorun"
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
            "evtx": EvtxJsonProcessor(),
            "disk": DiskProcessor(),
            "lnk": LnkJsonProcessor(),
            "registry": RegistryJsonProcessor(),
            "network": NetworkProcessor(),
            "processes": ProcessesProcessor()
        }

        actions_generator = find_and_process_files(
            source_dir=args.source_dir,
            processors=processors,
            artefact_patterns=ARTEFACT_PATTERNS,
            target_indices=target_indices,
            machine_name=machine_name
        )

        uploader.streaming_bulk_upload(actions_generator, chunk_size=args.chunk_size)

    except (FileNotFoundError, ConnectionError) as e:
        print(f"\n[ERREUR] {e}")
    except Exception as e:
        import traceback

        print(f"\n[ERREUR INATTENDUE] Une erreur est survenue : {e}")
        traceback.print_exc()
