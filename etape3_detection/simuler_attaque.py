import json
import time
from confluent_kafka import Producer

# Configuration Kafka
conf = {'bootstrap.servers': '127.0.0.1:9092'}
producer = Producer(conf)

def envoyer_paquet(ip_src, port_dst, taille):
    data = {
        "ip_src": ip_src,
        "ip_dst": "192.168.1.100",
        "port_dst": port_dst,
        "protocole": "TCP",
        "taille": taille
    }
    # On utilise l'IP comme clé pour le partitionnement Kafka
    producer.produce('paquets_reseau', key=ip_src, value=json.dumps(data))

# --- DÉBUT DE LA SIMULATION PARAMÉTRABLE ---

print("🔥 Lancement d'une simulation MASSIVE de DDoS...")

# 1. ATTAQUE DDOS TRÈS LONGUE (Va générer beaucoup d'alertes)
# Seuil de détection = 20 paquets. 
# En envoyant 200 paquets, on va générer 10 alertes DDoS.
for i in range(200): 
    envoyer_paquet("200.200.200.200", 80, 64)
    if i % 50 == 0: producer.flush() # Vider le tampon régulièrement
print("✅ DDoS envoyé (10 alertes théoriques)")

# 2. ATTAQUE PORT SCAN MODÉRÉE
# Seuil = 5 ports.
# En envoyant vers 15 ports, on va générer 3 alertes Port Scan.
for port in range(1, 16): 
    envoyer_paquet("201.201.201.201", port, 64)
print("✅ Port Scan envoyé (3 alertes théoriques)")

# 3. ATTAQUE FLOOD LÉGÈRE
# Seuil = 15 000 bytes. 
# En envoyant 15 paquets de 1400 bytes (21 000 bytes), on génère 1 seule alerte.
for _ in range(15):
    envoyer_paquet("202.202.202.202", 443, 1400)
print("✅ Flood envoyé (1 alerte théorique)")

# Finalisation
producer.flush()
print("-" * 30)
print("🚀 Simulation terminée ! Regardez le Dashboard.")