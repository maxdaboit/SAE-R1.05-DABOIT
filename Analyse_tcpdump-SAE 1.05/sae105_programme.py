# --- sae105_programme.py ---
# -*- coding: utf-8 -*-

"""
Module d'analyse tcpdump (texte) - SAE 1.05

Objectifs :
- Parser proprement une sortie texte de tcpdump (IP / IP6, TCP/UDP/ICMP/OTHER)
- Extraire flags TCP, longueur "length N" et quelques variantes DNS
- Calculer des statistiques (par source, destination, port, proto, volume)
- Détecter des comportements suspects :
  * Scan de ports
  * Possible DoS
  * Possible SYN flood
  * Sources "noisy" (bavardes)
- Produire :
  * Images (base64) pour affichage dans Flask (matplotlib backend Agg)
  * Rapport Markdown structuré (titres Markdown + tables + listes)
"""

from __future__ import annotations

import base64
import io
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


# -----------------------------------------------------------------------------
# Matplotlib : backend non-GUI pour serveur Flask
# -----------------------------------------------------------------------------
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


# -----------------------------------------------------------------------------
# Langue (pilotée par app.py via core.current_lang = session["lang"])
# -----------------------------------------------------------------------------
current_lang = "fr"


# -----------------------------------------------------------------------------
# Textes FR/EN (pour le rapport)
# -----------------------------------------------------------------------------
TEXTS = {
    "fr": {
        "md_title": "Rapport d'analyse du trafic réseau",
        "md_summary_title": "Résumé général",
        "md_info_title": "Informations générales sur la capture",
        "md_proto_title": "Répartition par protocole",
        "md_tcp_title": "Comportement des connexions TCP",
        "md_syn_title": "Répartition des paquets SYN par destination",
        "md_src_title": "Hôtes émetteurs principaux",
        "md_dst_title": "Hôtes destinataires principaux",
        "md_ports_title": "Ports de destination les plus utilisés",
        "md_alerts_title": "Alertes détectées",
        "md_main_acts": "Activités suspectes principales",
        "summary_none": (
            "Aucune activité suspecte n'a été clairement mise en évidence avec les seuils actuels. "
            "Le trafic observé semble globalement normal."
        ),
        "summary_intro": "Voici un résumé des principaux éléments détectés dans la capture :",
        "scan_title": "Suspicion de scan de ports",
        "scan_line": "{src} semble tester un grand nombre de ports sur {dst}.",
        "dos_title": "Suspicion de déni de service (DoS)",
        "dos_line": "Une grosse partie du trafic est dirigée vers {dst}, ce qui peut indiquer une tentative de saturation.",
        "syn_title": "Suspicion de SYN flood",
        "syn_line": "Le nombre de paquets SYN vers {dst} est très élevé par rapport au reste du trafic.",
        "noisy_title": "Présence de sources très bavardes",
        "noisy_line": "{src} émet un volume important de paquets ou contacte beaucoup de destinations différentes.",
        "summary_context": (
            "Ces observations doivent être replacées dans le contexte du réseau :\n"
            "- il peut s'agir d'attaques réelles,\n"
            "- ou d'applications légitimes très actives (sauvegardes, mises à jour, etc.)."
        ),
        "host_prefix": "hôte",
    },
    "en": {
        "md_title": "Network traffic analysis report",
        "md_summary_title": "General summary",
        "md_info_title": "General information about the capture",
        "md_proto_title": "Protocol distribution",
        "md_tcp_title": "TCP connection behaviour",
        "md_syn_title": "SYN packets by destination",
        "md_src_title": "Main source hosts",
        "md_dst_title": "Main destination hosts",
        "md_ports_title": "Most used destination ports",
        "md_alerts_title": "Detected alerts",
        "md_main_acts": "Main suspicious activities",
        "summary_none": "No clearly suspicious activity was found with the current thresholds. The observed traffic looks mostly normal.",
        "summary_intro": "Here is a summary of the main elements detected in the capture:",
        "scan_title": "Suspected port scan",
        "scan_line": "{src} seems to be testing many ports on {dst}.",
        "dos_title": "Suspected denial of service (DoS)",
        "dos_line": "A large part of the traffic is directed to {dst}, which may indicate an attempt to overload it.",
        "syn_title": "Suspected SYN flood",
        "syn_line": "The number of SYN packets to {dst} is very high compared to the rest of the traffic.",
        "noisy_title": "Presence of very talkative sources",
        "noisy_line": "{src} sends a large number of packets or contacts many different destinations.",
        "summary_context": (
            "These observations must be interpreted in the context of the network:\n"
            "- they may correspond to real attacks,\n"
            "- or to legitimate but very active applications (backups, updates, etc.)."
        ),
        "host_prefix": "host",
    },
}


# -----------------------------------------------------------------------------
# Seuils par défaut (Flask les lit)
# -----------------------------------------------------------------------------
DEFAULT_SCAN_PORTS = 20
DEFAULT_DOS_ABS = 1000
DEFAULT_DOS_PCT = 30  # en %
DEFAULT_NOISY_DESTS = 50
DEFAULT_NOISY_PKTS = 80
DEFAULT_SYN_ABS = 500
DEFAULT_SYN_RATIO = 50  # en %


# -----------------------------------------------------------------------------
# Regex parsing tcpdump
# -----------------------------------------------------------------------------
LINE_RE = re.compile(
    r"^(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"IP6?\s+(?P<src>\S+)\s*>\s*(?P<dst>\S+):\s*"
    r"(?P<rest>.*)$"
)

FLAGS_RE = re.compile(r"Flags\s+\[(?P<flags>[^\]]+)\]")
LEN_RE = re.compile(r"\blength\s+(?P<length>\d+)\b")

# DNS avec hexdump sur la même ligne: "... 46 0x0000 ..."
DNS_HEX_LEN_RE = re.compile(r"\s(?P<length>\d+)\s+0x[0-9a-fA-F]{4}\b")

# DNS parfois affiché comme "(46)" en fin de ligne
DNS_PAREN_LEN_RE = re.compile(r"\((?P<length>\d+)\)\s*$")

# fallback si nombre en fin de ligne
TRAILING_NUM_RE = re.compile(r"(?P<length>\d+)\s*$")


def _t() -> Dict[str, str]:
    """Raccourci pour récupérer le dictionnaire de traductions."""
    return TEXTS.get(current_lang, TEXTS["fr"])


def _parse_time(timestr: str) -> Optional[datetime]:
    """
    Tente de parser HH:MM:SS.sss ou HH:MM:SS.
    Note : ce timestamp n'a pas de date -> on l'utilise surtout pour durée relative.
    """
    try:
        return datetime.strptime(timestr, "%H:%M:%S.%f")
    except ValueError:
        try:
            return datetime.strptime(timestr, "%H:%M:%S")
        except ValueError:
            return None


PortType = Union[int, str, None]


def split_host_port(field: str) -> Tuple[str, PortType]:
    """
    Découpe "host.port" en (host, port).
    - Si port est numérique -> int
    - Sinon (ssh/http/domain/...) -> str
    - Si pas de point -> port = None
    """
    field = field.strip()
    if "." not in field:
        return field, None

    host, last = field.rsplit(".", 1)
    if last.isdigit():
        return host, int(last)
    return host, last


def _detect_proto(src_raw: str, dst_raw: str, rest: str, flags: Optional[str]) -> str:
    """
    Heuristique volontairement simple :
    - flags => TCP
    - mots-clés DNS ou suffixe .domain => UDP
    - "ICMP" => ICMP
    - sinon OTHER
    """
    if flags is not None:
        return "TCP"

    # DNS : on repère quelques tokens tcpdump typiques
    if (" NXDomain" in rest) or (" PTR?" in rest) or (" A?" in rest) or src_raw.endswith(".domain") or dst_raw.endswith(".domain"):
        return "UDP"

    if "ICMP" in rest:
        return "ICMP"

    return "OTHER"


def _extract_length(rest: str, proto: str) -> Optional[int]:
    """
    Extrait la longueur de paquet.
    - TCP: "length N"
    - DNS/UDP: formats possibles dans les dumps :
      1) "... 46 0x0000 ..." (hexdump sur la même ligne)
      2) "... (46)" (taille entre parenthèses en fin de ligne)
      3) "... 46" (nombre en fin de ligne)
    """
    m = LEN_RE.search(rest)
    if m:
        return int(m.group("length"))

    if proto == "UDP":
        mp = DNS_PAREN_LEN_RE.search(rest)
        if mp:
            return int(mp.group("length"))

        mx = DNS_HEX_LEN_RE.search(rest)
        if mx:
            return int(mx.group("length"))

        mt = TRAILING_NUM_RE.search(rest)
        if mt:
            return int(mt.group("length"))

    return None


def parse_tcpdump_file(path: Union[str, Path]) -> Tuple[List[Dict[str, Any]], Optional[datetime], Optional[datetime]]:
    """
    Parse un fichier texte tcpdump (avec ou sans hexdump).
    On ne garde que les lignes qui matchent LINE_RE (timestamp + IP/IP6).
    """
    path = Path(path)
    packets: List[Dict[str, Any]] = []
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            m = LINE_RE.match(line)
            if not m:
                # Ignore les lignes hexdump "0x0000 ..." et autres.
                continue

            timestr = m.group("time")
            src_raw = m.group("src")
            dst_raw = m.group("dst")
            rest = m.group("rest")

            fm = FLAGS_RE.search(rest)
            flags = fm.group("flags") if fm else None

            proto = _detect_proto(src_raw, dst_raw, rest, flags)
            length = _extract_length(rest, proto)

            ts = _parse_time(timestr)
            if ts:
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts

            src_host, src_port = split_host_port(src_raw)
            dst_host, dst_port = split_host_port(dst_raw)

            packets.append(
                {
                    "time": timestr,
                    "src_host": src_host,
                    "src_port": src_port,
                    "dst_host": dst_host,
                    "dst_port": dst_port,
                    "flags": flags,
                    "length": length,  # None possible
                    "proto": proto,
                    "raw_line": line,
                }
            )

    return packets, first_ts, last_ts


# -----------------------------------------------------------------------------
# Stats
# -----------------------------------------------------------------------------
def is_syn_flag(flags: Optional[str]) -> bool:
    """Détecte un SYN via la présence de 'S' dans les flags tcpdump."""
    return bool(flags) and ("S" in flags)


def compute_stats(packets: List[Dict[str, Any]]):
    """
    Calcule des compteurs utiles.
    Retourne une tuple (compat app.py).
    """
    by_src = Counter()
    by_dst = Counter()
    by_dport = Counter()
    by_flow = Counter()  # (src_host, dst_host, dst_port) -> count
    dests_per_src = defaultdict(set)

    total_bytes = 0
    flags_counter = Counter()
    syn_per_dst = Counter()
    syn_total = 0
    by_proto = Counter()
    bytes_per_src = Counter()

    for p in packets:
        sh = p.get("src_host")
        dh = p.get("dst_host")
        dp = p.get("dst_port")
        flags = p.get("flags")
        proto = p.get("proto", "OTHER")

        pktlen = p.get("length") or 0  # None -> 0

        by_src[sh] += 1
        by_dst[dh] += 1
        by_proto[proto] += 1

        if dp is not None:
            by_dport[dp] += 1
            by_flow[(sh, dh, dp)] += 1

        dests_per_src[sh].add(dh)

        total_bytes += pktlen
        bytes_per_src[sh] += pktlen

        if flags:
            flags_counter[flags] += 1
            if is_syn_flag(flags):
                syn_per_dst[dh] += 1
                syn_total += 1

    flows_per_src = Counter({s: len(dsts) for s, dsts in dests_per_src.items()})

    return (
        by_src,
        by_dst,
        by_dport,
        by_flow,
        flows_per_src,
        total_bytes,
        flags_counter,
        syn_per_dst,
        syn_total,
        by_proto,
        bytes_per_src,
    )


# -----------------------------------------------------------------------------
# Détections
# -----------------------------------------------------------------------------
def detect_port_scans(by_flow: Counter, threshold_ports: int = DEFAULT_SCAN_PORTS) -> List[Dict[str, Any]]:
    """
    Détecte un scan "simple" :
    - si une même source contacte une même destination sur >= threshold_ports ports distincts.
    - on ignore les ports non numériques (ssh/http/domain...) pour éviter des faux positifs.
    """
    ports_per_pair = defaultdict(set)

    for (sh, dh, dp), _count in by_flow.items():
        if dp is None:
            continue
        if not isinstance(dp, int):
            continue
        ports_per_pair[(sh, dh)].add(dp)

    alerts = []
    for (sh, dh), ports in ports_per_pair.items():
        if len(ports) >= threshold_ports:
            alerts.append(
                {
                    "type": "PORTSCAN",
                    "src": sh,
                    "dst": dh,
                    "unique_dst_ports": len(ports),
                }
            )
    return alerts


def detect_dos(by_dst: Counter, abs_threshold: int = DEFAULT_DOS_ABS, pct_threshold: float = DEFAULT_DOS_PCT / 100.0) -> List[Dict[str, Any]]:
    """
    Détecte un possible DoS :
    - soit un volume absolu >= abs_threshold vers une destination
    - soit une proportion >= pct_threshold du trafic total
    """
    alerts = []
    total = sum(by_dst.values())
    for dst, count in by_dst.items():
        ratio = (count / total) if total else 0.0
        if count >= abs_threshold or ratio >= pct_threshold:
            alerts.append(
                {
                    "type": "POSSIBLE_DOS",
                    "dst": dst,
                    "packets": count,
                    "ratio": ratio,
                }
            )
    return alerts


def detect_noisy_sources(
    by_src: Counter,
    flows_per_src: Counter,
    dest_threshold: int = DEFAULT_NOISY_DESTS,
    pkt_threshold: int = DEFAULT_NOISY_PKTS,
) -> List[Dict[str, Any]]:
    """
    Détecte une source "noisy" si :
    - elle contacte trop de destinations distinctes (>= dest_threshold)
    - ou elle envoie trop de paquets (>= pkt_threshold)
    """
    alerts = []
    for src, pkts in by_src.items():
        ndests = flows_per_src.get(src, 0)
        if ndests >= dest_threshold or pkts >= pkt_threshold:
            alerts.append(
                {
                    "type": "NOISY_SOURCE",
                    "src": src,
                    "distinct_dests": ndests,
                    "packets": pkts,
                }
            )
    return alerts


def detect_syn_flood(
    syn_per_dst: Counter,
    by_dst: Counter,
    syn_abs: int = DEFAULT_SYN_ABS,
    syn_ratio: float = DEFAULT_SYN_RATIO / 100.0,
) -> List[Dict[str, Any]]:
    """
    Détecte un possible SYN flood :
    - nombre de SYN vers une cible >= syn_abs
    - et ratio SYN/total vers cette cible >= syn_ratio
    """
    alerts = []
    for dst, syn_count in syn_per_dst.items():
        total_to_dst = by_dst.get(dst, 0)
        if total_to_dst <= 0:
            continue

        ratio = syn_count / total_to_dst
        if syn_count >= syn_abs and ratio >= syn_ratio:
            alerts.append(
                {
                    "type": "POSSIBLE_SYN_FLOOD",
                    "dst": dst,
                    "syn_packets": syn_count,
                    "total_packets_to_dst": total_to_dst,
                    "syn_ratio": ratio,
                }
            )
    return alerts


# -----------------------------------------------------------------------------
# Normalisation compat (ancien/nouveau)
# -----------------------------------------------------------------------------
def _normalize_alert(a: Dict[str, Any]) -> Dict[str, Any]:
    """
    Objectif : supporter les anciens formats (sans underscore) et les nouveaux.

    Exemples "anciens" vus dans l'ancien script :
      - POSSIBLEDOS au lieu de POSSIBLE_DOS
      - NOISYSOURCE au lieu de NOISY_SOURCE
      - POSSIBLESYNFLOOD au lieu de POSSIBLE_SYN_FLOOD
      - uniquedstports au lieu de unique_dst_ports
      - synpackets / synratio ... etc.
    [file:95]
    """
    out = dict(a)  # copie

    typ = (out.get("type") or "").upper()

    # Unifier les types
    aliases = {
        "POSSIBLEDOS": "POSSIBLE_DOS",
        "NOISYSOURCE": "NOISY_SOURCE",
        "POSSIBLESYNFLOOD": "POSSIBLE_SYN_FLOOD",
    }
    typ = aliases.get(typ, typ)
    out["type"] = typ

    # Unifier certaines clés
    if "uniquedstports" in out and "unique_dst_ports" not in out:
        out["unique_dst_ports"] = out["uniquedstports"]
    if "synpackets" in out and "syn_packets" not in out:
        out["syn_packets"] = out["synpackets"]
    if "synratio" in out and "syn_ratio" not in out:
        out["syn_ratio"] = out["synratio"]
    if "totalpacketstodst" in out and "total_packets_to_dst" not in out:
        out["total_packets_to_dst"] = out["totalpacketstodst"]
    if "distinctdests" in out and "distinct_dests" not in out:
        out["distinct_dests"] = out["distinctdests"]

    return out


# -----------------------------------------------------------------------------
# Graphes (base64)
# -----------------------------------------------------------------------------
def _fig_to_base64(fig) -> str:
    """Convertit une figure matplotlib en PNG base64 (pour <img src="data:...">)."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight")
    buf.seek(0)
    out = base64.b64encode(buf.read()).decode("ascii")
    plt.close(fig)
    return out


def build_chart_images(by_src: Counter, by_dst: Counter, by_dport: Counter, bytes_per_src: Counter) -> Dict[str, str]:
    """
    Génère quelques graphes "top N" et renvoie un dict {key: base64_png}.
    Clés attendues par rapport.html :
      - traffic_by_dst
      - top_sources
      - top_ports
      - top_sources_bytes
    """
    images: Dict[str, str] = {}
    lang_fr = current_lang == "fr"

    # Camembert destination
    if by_dst:
        labels, sizes = [], []
        top = by_dst.most_common(5)
        for dst, c in top:
            labels.append(str(dst))
            sizes.append(c)
        other = sum(by_dst.values()) - sum(sizes)
        if other > 0:
            labels.append("Autres" if lang_fr else "Others")
            sizes.append(other)

        fig, ax = plt.subplots(figsize=(4, 4))
        ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
        ax.set_title("Répartition du trafic par destination" if lang_fr else "Traffic by destination")
        images["traffic_by_dst"] = _fig_to_base64(fig)

    # Top sources
    if by_src:
        top = by_src.most_common(8)
        labels = [str(h) for h, _ in top]
        values = [c for _, c in top]

        fig, ax = plt.subplots(figsize=(5, 3))
        ax.bar(range(len(labels)), values)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
        ax.set_ylabel("Paquets" if lang_fr else "Packets")
        ax.set_title("Principales sources de trafic" if lang_fr else "Main traffic sources")
        images["top_sources"] = _fig_to_base64(fig)

    # Top ports
    if by_dport:
        top = by_dport.most_common(8)
        labels = [str(p) for p, _ in top]
        values = [c for _, c in top]

        fig, ax = plt.subplots(figsize=(5, 3))
        ax.bar(range(len(labels)), values)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
        ax.set_ylabel("Paquets" if lang_fr else "Packets")
        ax.set_title("Ports de destination les plus utilisés" if lang_fr else "Most used destination ports")
        images["top_ports"] = _fig_to_base64(fig)

    # Top sources par volume
    if bytes_per_src:
        top = bytes_per_src.most_common(8)
        labels = [str(s) for s, _ in top]
        values = [v / 1024.0 for _, v in top]  # Ko/KB

        fig, ax = plt.subplots(figsize=(5, 3))
        ax.bar(range(len(labels)), values)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
        ax.set_ylabel("Volume (Ko)" if lang_fr else "Volume (KB)")
        ax.set_title("Top sources par volume" if lang_fr else "Top sources by volume")
        images["top_sources_bytes"] = _fig_to_base64(fig)

    return images


# -----------------------------------------------------------------------------
# Rapport Markdown
# -----------------------------------------------------------------------------
def _host_label(name: str) -> str:
    """
    Affiche :
    - un hostname tel quel (si contient des lettres)
    - sinon "hôte X" / "host X"
    """
    t = _t()
    if any(c.isalpha() for c in name):
        return name
    return f"{t['host_prefix']} {name}"


def _build_summary(alerts: List[Dict[str, Any]]) -> str:
    """
    Génère un résumé Markdown lisible avec :
    - une intro
    - des sous-titres (###)
    - des puces (- ...)
    """
    t = _t()
    if not alerts:
        return t["summary_none"]

    # Normaliser avant traitement (compat ancien/nouveau)
    alerts_n = [_normalize_alert(a) for a in alerts]

    scan_entries: List[str] = []
    dos_entries: List[str] = []
    syn_entries: List[str] = []
    noisy_entries: List[str] = []

    # Dédoublonnage (garde l'ordre)
    def dedupe(items: List[str]) -> List[str]:
        seen = set()
        out = []
        for x in items:
            if x in seen:
                continue
            seen.add(x)
            out.append(x)
        return out

    for a in alerts_n:
        typ = a.get("type")

        if typ == "PORTSCAN":
            scan_entries.append(t["scan_line"].format(src=_host_label(a["src"]), dst=_host_label(a["dst"])))
        elif typ == "POSSIBLE_DOS":
            dos_entries.append(t["dos_line"].format(dst=_host_label(a["dst"])))
        elif typ == "POSSIBLE_SYN_FLOOD":
            syn_entries.append(t["syn_line"].format(dst=_host_label(a["dst"])))
        elif typ == "NOISY_SOURCE":
            noisy_entries.append(t["noisy_line"].format(src=_host_label(a["src"])))

    lines: List[str] = []
    lines.append(t["summary_intro"])
    lines.append("")

    def section(title: str, entries: List[str]) -> None:
        if not entries:
            return
        lines.append(f"### {title}")
        for e in dedupe(entries):
            lines.append(f"- {e}")
        lines.append("")

    section(t["scan_title"], scan_entries)
    section(t["dos_title"], dos_entries)
    section(t["syn_title"], syn_entries)
    section(t["noisy_title"], noisy_entries)

    lines.append(t["summary_context"])
    return "\n".join(lines)


def build_markdown_report(
    packets: List[Dict[str, Any]],
    by_src: Counter,
    by_dst: Counter,
    by_dport: Counter,
    by_flow: Counter,
    alerts: List[Dict[str, Any]],
    first_ts: Optional[datetime],
    last_ts: Optional[datetime],
    total_bytes: int,
    flags_counter: Counter,
    syn_per_dst: Counter,
    syn_total: int,
    by_proto: Counter,
) -> str:
    """
    Construit un rapport Markdown structuré :
    - # titre
    - ## sections
    - tables Markdown (compat markdown + extension "tables")
    """
    t = _t()

    total_packets = len(packets)

    if first_ts and last_ts and last_ts >= first_ts:
        duration_sec = (last_ts - first_ts).total_seconds()
    else:
        duration_sec = 0.0

    pps = (total_packets / duration_sec) if duration_sec > 0 else 0.0

    # Normaliser les alertes pour être robuste
    alerts_n = [_normalize_alert(a) for a in alerts]

    lines: List[str] = []

    # -------------------------------------------------------------------------
    # Titre
    # -------------------------------------------------------------------------
    lines.append(f"# {t['md_title']}")
    lines.append("")

    # -------------------------------------------------------------------------
    # Résumé
    # -------------------------------------------------------------------------
    lines.append(f"## {t['md_summary_title']}")
    lines.append(_build_summary(alerts_n))
    lines.append("")

    # -------------------------------------------------------------------------
    # Infos capture
    # -------------------------------------------------------------------------
    lines.append(f"## {t['md_info_title']}")
    lines.append("")
    if current_lang == "fr":
        lines.append("| Élément | Valeur |")
    else:
        lines.append("| Element | Value |")
    lines.append("|---|---|")

    lines.append(f"| {'Paquets analysés' if current_lang=='fr' else 'Packets analysed'} | {total_packets} |")
    lines.append(f"| {'Volume total' if current_lang=='fr' else 'Total volume'} | {total_bytes} {'octets' if current_lang=='fr' else 'bytes'} |")

    if first_ts and last_ts:
        lines.append(f"| {'Premier paquet' if current_lang=='fr' else 'First packet'} | {first_ts.time()} |")
        lines.append(f"| {'Dernier paquet' if current_lang=='fr' else 'Last packet'} | {last_ts.time()} |")
        lines.append(f"| {'Durée de la capture' if current_lang=='fr' else 'Capture duration'} | {duration_sec:.3f} s |")
    else:
        lines.append(
            f"| {'Horodatages' if current_lang=='fr' else 'Timestamps'} | "
            f"{'Non disponibles' if current_lang=='fr' else 'Not available'} |"
        )

    lines.append(f"| {'Débit moyen' if current_lang=='fr' else 'Average rate'} | {pps:.3f} {'paquets/s' if current_lang=='fr' else 'packets/s'} |")
    lines.append(f"| {'Paquets SYN totaux' if current_lang=='fr' else 'Total SYN packets'} | {syn_total} |")
    lines.append("")

    # -------------------------------------------------------------------------
    # Protocoles
    # -------------------------------------------------------------------------
    lines.append(f"## {t['md_proto_title']}")
    lines.append("")
    lines.append(f"| {'Protocole' if current_lang=='fr' else 'Protocol'} | {'Paquets' if current_lang=='fr' else 'Packets'} |")
    lines.append("|---|---:|")
    for proto, c in by_proto.most_common():
        lines.append(f"| {proto} | {c} |")
    lines.append("")

    # -------------------------------------------------------------------------
    # TCP flags
    # -------------------------------------------------------------------------
    lines.append(f"## {t['md_tcp_title']}")
    lines.append("")
    if not flags_counter:
        lines.append("Aucun flag TCP identifié." if current_lang == "fr" else "No TCP flags identified.")
    else:
        lines.append(f"| Flags | {'Nombre de paquets' if current_lang=='fr' else 'Packets'} |")
        lines.append("|---|---:|")
        for fl, c in flags_counter.most_common():
            lines.append(f"| {fl} | {c} |")
    lines.append("")

    # -------------------------------------------------------------------------
    # SYN par destination
    # -------------------------------------------------------------------------
    lines.append(f"## {t['md_syn_title']}")
    lines.append("")
    if not syn_per_dst:
        lines.append("Aucun paquet SYN distinct." if current_lang == "fr" else "No SYN packet detected.")
    else:
        lines.append(f"| {'Destination' if current_lang=='fr' else 'Destination'} | SYN | Total | Ratio |")
        lines.append("|---|---:|---:|---:|")
        for dst, syn_count in syn_per_dst.most_common():
            total_to_dst = by_dst.get(dst, 0)
            ratio = (syn_count / total_to_dst) if total_to_dst else 0.0
            lines.append(f"| {dst} | {syn_count} | {total_to_dst} | {ratio:.2f} |")
    lines.append("")

    # -------------------------------------------------------------------------
    # Top sources / destinations / ports
    # -------------------------------------------------------------------------
    lines.append(f"## {t['md_src_title']}")
    lines.append("")
    lines.append(f"| {'Source' if current_lang=='fr' else 'Source'} | {'Paquets' if current_lang=='fr' else 'Packets'} |")
    lines.append("|---|---:|")
    for host, c in by_src.most_common(10):
        lines.append(f"| {host} | {c} |")
    lines.append("")

    lines.append(f"## {t['md_dst_title']}")
    lines.append("")
    lines.append(f"| {'Destination' if current_lang=='fr' else 'Destination'} | {'Paquets' if current_lang=='fr' else 'Packets'} |")
    lines.append("|---|---:|")
    for host, c in by_dst.most_common(10):
        lines.append(f"| {host} | {c} |")
    lines.append("")

    lines.append(f"## {t['md_ports_title']}")
    lines.append("")
    lines.append(f"| {'Port' if current_lang=='fr' else 'Port'} | {'Paquets' if current_lang=='fr' else 'Packets'} |")
    lines.append("|---|---:|")
    for port, c in by_dport.most_common(10):
        lines.append(f"| {port} | {c} |")
    lines.append("")

    # -------------------------------------------------------------------------
    # Alertes détaillées
    # -------------------------------------------------------------------------
    lines.append(f"## {t['md_alerts_title']}")
    lines.append("")
    if not alerts_n:
        lines.append("Aucune alerte avec les seuils actuels." if current_lang == "fr" else "No alert with current thresholds.")
    else:
        lines.append(f"| {'Type' if current_lang=='fr' else 'Type'} | {'Détail' if current_lang=='fr' else 'Detail'} |")
        lines.append("|---|---|")

        for a in alerts_n:
            typ = a.get("type", "ALERT")

            if typ == "PORTSCAN":
                detail = (
                    f"{_host_label(a['src'])} teste {a['unique_dst_ports']} ports sur {_host_label(a['dst'])}."
                    if current_lang == "fr"
                    else f"{_host_label(a['src'])} is testing {a['unique_dst_ports']} ports on {_host_label(a['dst'])}."
                )

            elif typ == "POSSIBLE_DOS":
                pct = round(float(a.get("ratio", 0.0)) * 100, 1)
                detail = (
                    f"DoS sur {_host_label(a['dst'])}: {a['packets']} paquets ({pct}%)."
                    if current_lang == "fr"
                    else f"DoS on {_host_label(a['dst'])}: {a['packets']} packets ({pct}%)."
                )

            elif typ == "POSSIBLE_SYN_FLOOD":
                pct = round(float(a.get("syn_ratio", 0.0)) * 100, 1)
                detail = (
                    f"SYN flood sur {_host_label(a['dst'])}: {a['syn_packets']} SYN ({pct}%)."
                    if current_lang == "fr"
                    else f"SYN flood on {_host_label(a['dst'])}: {a['syn_packets']} SYN ({pct}%)."
                )

            elif typ == "NOISY_SOURCE":
                detail = (
                    f"{_host_label(a['src'])}: {a['distinct_dests']} dests, {a['packets']} paquets."
                    if current_lang == "fr"
                    else f"{_host_label(a['src'])}: {a['distinct_dests']} dests, {a['packets']} packets."
                )

            else:
                detail = str(a)

            lines.append(f"| {typ} | {detail} |")

    lines.append("")

    # -------------------------------------------------------------------------
    # Activités suspectes principales (2 max)
    # -------------------------------------------------------------------------
    lines.append(f"## {t['md_main_acts']}")
    lines.append("")
    if not alerts_n:
        lines.append("- " + ("Aucune activité clairement suspecte avec les seuils actuels." if current_lang == "fr" else "No clearly suspicious activity with current thresholds."))
    else:
        count = 0
        for a in alerts_n:
            typ = a.get("type")

            if typ == "POSSIBLE_DOS":
                pct = round(float(a.get("ratio", 0.0)) * 100, 1)
                lines.append(
                    f"- Possible DoS vers {_host_label(a['dst'])} avec {a['packets']} paquets ({pct} % du trafic)."
                    if current_lang == "fr"
                    else f"- Possible DoS to {_host_label(a['dst'])} with {a['packets']} packets ({pct}% of traffic)."
                )
                count += 1

            elif typ == "PORTSCAN":
                lines.append(
                    f"- Scan de ports depuis {_host_label(a['src'])} vers {_host_label(a['dst'])}."
                    if current_lang == "fr"
                    else f"- Port scan from {_host_label(a['src'])} to {_host_label(a['dst'])}."
                )
                count += 1

            elif typ == "POSSIBLE_SYN_FLOOD":
                pct = round(float(a.get("syn_ratio", 0.0)) * 100, 1)
                lines.append(
                    f"- Possible SYN flood vers {_host_label(a['dst'])} ({a['syn_packets']} SYN, {pct}%)."
                    if current_lang == "fr"
                    else f"- Possible SYN flood to {_host_label(a['dst'])} ({a['syn_packets']} SYN, {pct}%)."
                )
                count += 1

            elif typ == "NOISY_SOURCE":
                lines.append(
                    f"- Source très bavarde : {_host_label(a['src'])}."
                    if current_lang == "fr"
                    else f"- Noisy source: {_host_label(a['src'])}."
                )
                count += 1

            if count >= 2:
                break

    return "\n".join(lines)
