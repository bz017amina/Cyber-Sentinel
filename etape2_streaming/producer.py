from scapy.all import sniff, IP, TCP, UDP
from kafka import KafkaProducer
import json
import datetime

producer = KafkaProducer(
    bootstrap_servers='127.0.0.1:9092',
    value_serializer=lambda x: json.dumps(x).encode('utf-8'),
    # On ajoute un serializer pour la clé (string -> bytes)
    key_serializer=lambda x: x.encode('utf-8'), 
    api_version=(3, 7, 0)
)

def analyser_paquet(paquet):
    if IP in paquet:
        ip_source = paquet[IP].src # On stocke l'IP source
        data = {
            "timestamp" : datetime.datetime.now().strftime("%H:%M:%S.%f"),
            "ip_src"    : ip_source,
            "ip_dst"    : paquet[IP].dst,
            "port_src"  : paquet.sport if (TCP in paquet or UDP in paquet) else 0,
            "port_dst"  : paquet.dport if (TCP in paquet or UDP in paquet) else 0,
            "protocole" : "TCP" if TCP in paquet else "UDP" if UDP in paquet else "Autre",
            "taille"    : len(paquet)
        }
        
        # IMPORTANT : On ajoute key=ip_source
        # Cela garantit que la même IP va toujours vers le même Consumer
        producer.send('paquets_reseau', key=ip_source, value=data)
        
        print(f"[ENVOYÉ] {data['ip_src']} → {data['ip_dst']} | {data['protocole']} | {data['taille']} bytes")

print("🚀 Producer démarré (Partitionnement par IP actif)...")
print("-" * 60)
sniff(prn=analyser_paquet, count=100, store=False) # Augmenté à 100 pour mieux voir les attaques
producer.flush()
print("✅ Paquets envoyés !")