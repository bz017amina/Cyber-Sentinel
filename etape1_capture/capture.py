from scapy.all import sniff, IP, TCP, UDP
import csv
import datetime

# Fichier de sortie
output_file = "flux_reseau.csv"

# Initialiser le CSV avec les en-têtes
with open(output_file, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "ip_src", "ip_dst", 
                     "port_src", "port_dst", "protocole", "taille"])

def analyser_paquet(paquet):
    if IP in paquet:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")
        ip_src    = paquet[IP].src
        ip_dst    = paquet[IP].dst
        taille    = len(paquet)
        protocole = "TCP" if TCP in paquet else "UDP" if UDP in paquet else "Autre"
        port_src  = paquet.sport if TCP in paquet or UDP in paquet else "-"
        port_dst  = paquet.dport if TCP in paquet or UDP in paquet else "-"

        # Affichage temps réel
        print(f"[{timestamp}] {ip_src}:{port_src} → {ip_dst}:{port_dst} | {protocole} | {taille} bytes")

        # Sauvegarde dans CSV
        with open(output_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, ip_src, ip_dst,
                             port_src, port_dst, protocole, taille])

# Lancer la capture
print("🔍 Capture en cours... (100 paquets)")
print("-" * 60)
sniff(prn=analyser_paquet, count=100, store=False)
print("-" * 60)
print(f"✅ Terminé ! Données sauvegardées dans {output_file}")