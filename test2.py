#!/usr/bin/env python3
import re
import csv
from collections import Counter, defaultdict
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox

# ---------------------------------------------------------
# Parsing des lignes tcpdump
# ---------------------------------------------------------

LINE_RE = re.compile(
    r'^(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP6?\s+'
    r'(?P<src>[^ >]+)\s*>\s*(?P<dst>[^:]+):\s*'
    r'(?:Flags\s*\[(?P<flags>[^\]]*)\].*?)?'
    r'(?:length\s+(?P<length>\d+))?'
)

HOST_PORT_RE = re.compile(r'^(?P<host>.+)\.(?P<port>[^.]+)$')


def split_host_port(field: str):
    m = HOST_PORT_RE.match(field)
    if not m:
        return field, None
    return m.group('host'), m.group('port')


def parse_tcpdump_file(path):
    packets = []
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or not line[0].isdigit():
                continue

            m = LINE_RE.match(line)
            if not m:
                continue

            gd = m.groupdict()
            time = gd['time']
            src_raw = gd['src']
            dst_raw = gd['dst']
            flags = gd.get('flags') or ''
            length = gd.get('length')
            length = int(length) if length is not None else 0

            src_host, src_port = split_host_port(src_raw)
            dst_host, dst_port = split_host_port(dst_raw)

            packets.append({
                'time': time,
                'src_host': src_host,
                'src_port': src_port,
                'dst_host': dst_host,
                'dst_port': dst_port,
                'flags': flags,
                'length': length,
            })
    return packets


# ---------------------------------------------------------
# Export CSV
# ---------------------------------------------------------

def export_csv(packets, out_path):
    if not packets:
        print("Aucun paquet parsé, CSV non généré.")
        return
    fields = list(packets[0].keys())
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(packets)
    print(f"CSV écrit dans {out_path}")


# ---------------------------------------------------------
# Statistiques et détection
# ---------------------------------------------------------

def compute_stats(packets):
    by_src = Counter()
    by_dst = Counter()
    by_dport = Counter()
    by_flow = Counter()
    dests_per_src = defaultdict(set)

    for p in packets:
        sh = p['src_host']
        dh = p['dst_host']
        dp = p['dst_port']

        by_src[sh] += 1
        by_dst[dh] += 1
        if dp:
            by_dport[dp] += 1
        by_flow[(sh, dh, dp)] += 1
        dests_per_src[sh].add(dh)

    flows_per_src = Counter({s: len(dests) for s, dests in dests_per_src.items()})
    return by_src, by_dst, by_dport, by_flow, flows_per_src


def detect_port_scans(by_flow, threshold_ports=20):
    ports_per_pair = defaultdict(set)
    for (sh, dh, dp), count in by_flow.items():
        if dp is None:
            continue
        ports_per_pair[(sh, dh)].add(dp)

    alerts = []
    for (sh, dh), ports in ports_per_pair.items():
        if len(ports) >= threshold_ports:
            alerts.append({
                'type': 'PORT_SCAN',
                'src': sh,
                'dst': dh,
                'unique_dst_ports': len(ports),
            })
    return alerts


def detect_dos(by_dst, abs_threshold=1000, pct_threshold=0.3):
    alerts = []
    total = sum(by_dst.values())

    for dst, count in by_dst.items():
        ratio = count / total if total else 0
        if count >= abs_threshold or ratio >= pct_threshold:
            alerts.append({
                'type': 'POSSIBLE_DOS',
                'dst': dst,
                'packets': count,
                'ratio': ratio,
            })
    return alerts


def detect_noisy_sources(by_src, flows_per_src, dest_threshold=50, pkt_threshold=80):
    alerts = []
    for src in by_src.keys():
        n_dests = flows_per_src.get(src, 0)
        pkts = by_src[src]
        if n_dests >= dest_threshold or pkts >= pkt_threshold:
            alerts.append({
                'type': 'NOISY_SOURCE',
                'src': src,
                'distinct_dests': n_dests,
                'packets': pkts,
            })
    return alerts


# ---------------------------------------------------------
# Rapport Markdown
# ---------------------------------------------------------

def generate_markdown_report(packets, by_src, by_dst, by_dport, alerts, out_path):
    total_packets = len(packets)

    lines = []
    lines.append("# Rapport d'analyse tcpdump\n\n")
    lines.append(f"Nombre total de paquets analysés : **{total_packets}**\n\n")

    lines.append("## Top IP sources\n\n")
    lines.append("| IP source | Paquets |\n| --- | --- |\n")
    for host, count in by_src.most_common(10):
        lines.append(f"| {host} | {count} |\n")

    lines.append("\n## Top IP destinations\n\n")
    lines.append("| IP destination | Paquets |\n| --- | --- |\n")
    for host, count in by_dst.most_common(10):
        lines.append(f"| {host} | {count} |\n")

    lines.append("\n## Top ports destination\n\n")
    lines.append("| Port | Paquets |\n| --- | --- |\n")
    for port, count in by_dport.most_common(10):
        lines.append(f"| {port} | {count} |\n")

    lines.append("\n## Alertes de sécurité détectées\n\n")
    if not alerts:
        lines.append("Aucune alerte détectée avec les seuils actuels.\n")
    else:
        lines.append("| Type | Détails |\n| --- | --- |\n")
        for a in alerts:
            if a['type'] == 'PORT_SCAN':
                detail = (
                    f"Scan de ports : {a['src']} -> {a['dst']} "
                    f"({a['unique_dst_ports']} ports différents)"
                )
            elif a['type'] == 'POSSIBLE_DOS':
                pct = round(a['ratio'] * 100, 1)
                detail = (
                    f"Possible DoS sur {a['dst']} : {a['packets']} paquets "
                    f"({pct}% du trafic)"
                )
            elif a['type'] == 'NOISY_SOURCE':
                detail = (
                    f"Source bavarde : {a['src']} "
                    f"(destinations={a['distinct_dests']}, paquets={a['packets']})"
                )
            else:
                detail = str(a)
            lines.append(f"| {a['type']} | {detail} |\n")

    with open(out_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)


# ---------------------------------------------------------
# GUI Tkinter
# ---------------------------------------------------------

def analyser_fichier():
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier tcpdump",
        filetypes=(("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*"))
    )
    if not chemin_fichier:
        return

    label_chemin.config(text=f"Fichier sélectionné : {chemin_fichier}")

    in_path = Path(chemin_fichier)
    packets = parse_tcpdump_file(in_path)

    if not packets:
        messagebox.showwarning("Analyse", "Aucun paquet n'a été parsé dans ce fichier.")
        return

    out_csv = in_path.with_suffix(".csv")
    out_md = in_path.with_suffix(".md")

    export_csv(packets, out_csv)
    by_src, by_dst, by_dport, by_flow, flows_per_src = compute_stats(packets)
    scans = detect_port_scans(by_flow, threshold_ports=20)
    dos = detect_dos(by_dst, abs_threshold=1000, pct_threshold=0.3)
    noisy = detect_noisy_sources(by_src, flows_per_src,
                                 dest_threshold=50, pkt_threshold=80)
    alerts = scans + dos + noisy

    generate_markdown_report(packets, by_src, by_dst, by_dport, alerts, out_md)

    messagebox.showinfo(
        "Analyse terminée",
        f"CSV généré : {out_csv}\nRapport Markdown : {out_md}\n"
        f"Alertes détectées : {len(alerts)}"
    )


def quitter():
    fenetre.destroy()


if __name__ == '__main__':
    fenetre = tk.Tk()
    fenetre.title("Analyse tcpdump - SAE 1.05")
    fenetre.geometry("500x200")

    btn_choisir = tk.Button(fenetre, text="Choisir un fichier tcpdump", command=analyser_fichier)
    btn_choisir.pack(pady=20)

    label_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné")
    label_chemin.pack(pady=10)

    btn_quitter = tk.Button(fenetre, text="Quitter", command=quitter)
    btn_quitter.pack(pady=10)

    fenetre.mainloop()
