import json
import torch
import datetime
from confluent_kafka import Consumer, Producer
from collections import defaultdict

# --- CONFIGURATION GPU ---
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"✅ MOTEUR DE DÉTECTION IDS ACTIF")
print(f"✅ APPAREIL UTILISÉ : {device}")

# --- CONFIGURATION KAFKA ---
# 1. Consommateur (pour lire les paquets réseau)
c_conf = {
    'bootstrap.servers': '127.0.0.1:9092',
    'group.id': 'ids_detection_final',
    'auto.offset.reset': 'latest'
}
consumer = Consumer(c_conf)
consumer.subscribe(['paquets_reseau'])

# 2. Producteur (pour envoyer les alertes au Dashboard)
p_conf = {'bootstrap.servers': '127.0.0.1:9092'}
alert_producer = Producer(p_conf)

# --- STATISTIQUES ET SEUILS ---
stats = defaultdict(lambda: {'nb': 0, 'ports': set(), 'vol': 0})

SEUIL_DDOS = 20       # paquets
SEUIL_SCAN = 5        # ports différents
SEUIL_FLOOD = 15000   # bytes

# Dans detection.py
import datetime # Assurez-vous que cet import est présent

def envoyer_alerte_dashboard(type_attaque, ip, nb_p, nb_pt):
    # On génère l'heure EXACTE du PC au moment de la détection
    heure_actuelle = datetime.datetime.now().strftime("%H:%M:%S")
    
    alerte_payload = {
        "timestamp": heure_actuelle, # <-- C'est l'heure de votre PC
        "type": type_attaque,
        "ip_source": ip,
        "ports": f"{nb_pt} ports / {nb_p} paquets"
    }
    alert_producer.produce('alertes_ids', value=json.dumps(alerte_payload))
    alert_producer.flush()

print("🔍 Analyse des flux en cours... (Prêt pour le Dashboard)")
print("-" * 60)

try:
    while True:
        msg = consumer.poll(0.1)
        if msg is None: continue
        if msg.error(): continue

        # Charger les données du paquet
        paquet = json.loads(msg.value().decode('utf-8'))
        ip_s = paquet['ip_src']
        port_d = paquet['port_dst']
        taille = paquet['taille']

        # 1. Mise à jour des statistiques
        stats[ip_s]['nb'] += 1
        stats[ip_s]['ports'].add(port_d)
        stats[ip_s]['vol'] += taille

        # 2. CRÉATION DU TENSEUR PYTORCH (Analyse GPU)
        features = torch.tensor([
            float(stats[ip_s]['nb']), 
            float(len(stats[ip_s]['ports'])), 
            float(stats[ip_s]['vol'])
        ]).to(device)

        # 3. LOGIQUE DE DÉTECTION
        alerte_detectee = False
        type_attaque = ""

        if features[0] >= SEUIL_DDOS:
            type_attaque = "DDoS"
            alerte_detectee = True
        elif features[1] >= SEUIL_SCAN:
            type_attaque = "Port Scan"
            alerte_detectee = True
        elif features[2] >= SEUIL_FLOOD:
            type_attaque = "Flood"
            alerte_detectee = True

        # 4. ACTION
        if alerte_detectee:
            print(f"🚨 ALERTE {type_attaque} détectée pour IP: {ip_s}")
            
            # APPEL DE L'ENVOI AU DASHBOARD
            envoyer_alerte_dashboard(
                type_attaque, 
                ip_s, 
                int(features[0]), 
                int(features[1])
            )
            
            # Réinitialisation des stats pour éviter de spammer l'alerte
            stats[ip_s] = {'nb': 0, 'ports': set(), 'vol': 0}
        else:
            # Affichage silencieux en mode console
            print(f"[OK] {ip_s} -> {port_d} ({taille} bytes)      ", end='\r')
except KeyboardInterrupt:
    print("\nArrêt du système de détection.")
finally:
    consumer.close()