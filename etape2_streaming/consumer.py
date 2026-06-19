from kafka import KafkaConsumer
import json

consumer = KafkaConsumer(
    'paquets_reseau',
    bootstrap_servers='127.0.0.1:9092',
    value_deserializer=lambda x: json.loads(x.decode('utf-8')),
    auto_offset_reset='latest',
    group_id='ids_group_3',
    api_version=(3, 7, 0)
)

print("👂 Consumer démarré — en attente de paquets...")
print("-" * 60)

for message in consumer:
    paquet = message.value
    print(f"[REÇU] {paquet['timestamp']} | "
          f"{paquet['ip_src']}:{paquet['port_src']} → "
          f"{paquet['ip_dst']}:{paquet['port_dst']} | "
          f"{paquet['protocole']} | {paquet['taille']} bytes")