# 🛡️ Cyber-Sentinel

## Système de Détection d'Intrusion Temps Réel

**Cyber-Sentinel** est un système de détection d'intrusion (IDS) temps réel qui combine la capture de trafic réseau, le streaming distribué avec Apache Kafka, l'analyse accélérée par GPU via PyTorch CUDA et la visualisation interactive à l'aide de Dash.

Projet académique réalisé dans le cadre du module **Systèmes Répartis** à la **Faculté des Sciences Ben M'Sick (FSBM)**.

### 🚀 Technologies utilisées

* Python 3.11
* Apache Kafka
* Scapy
* PyTorch (CUDA)
* Dash & Plotly

### 📂 Architecture

```text
Capture Réseau → Kafka → Détection GPU → Dashboard
```

### 🎯 Fonctionnalités

* Capture du trafic réseau en temps réel
* Streaming des données avec Kafka
* Détection d'attaques (DDoS, Flood, Port Scan)
* Visualisation des alertes via un Dashboard interactif

### ▶️ Lancement

```bash
python etape1_capture/capture.py
python etape2_streaming/producer.py
python etape3_detection/detection.py
python etape4_dashboard/dashboard.py
```

### 📚 Contexte

Ce projet démontre l'utilisation des systèmes distribués, du streaming temps réel et de l'accélération GPU pour la cybersécurité moderne.
