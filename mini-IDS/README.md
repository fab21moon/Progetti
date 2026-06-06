
# Network IDS & Traffic Detector (Python / Scapy)

Un piccolo **Intrusion Detection System (IDS)** embrionale sviluppato in Python. Il tool è in grado di intercettare il traffico di rete in tempo reale sulla scheda di rete locale, analizzare la struttura dei pacchetti nei livelli IP e TCP/UDP, e applicare regole di security per identificare potenziali minacce o anomalie di configurazione.

Gli alert generati vengono stampati a terminale e storicizzati in un file log in formato strutturato (JSON), pronto per essere indicizzato da sistemi SIEM (es. Splunk o ELK Stack).

## 🚀 Funzionalità Principali

* **Live Packet Sniffing:** Cattura in tempo reale del traffico di rete sfruttando le capacità a basso livello della libreria `Scapy`.
* **Deep Packet Inspection (DPI) Essenziale:** Smontaggio dei pacchetti per estrarre indirizzi IP (Sorgente/Destinazione) e porte di trasporto (TCP/UDP).
* **Rilevamento Protocolli Non Sicuri:** Monitoraggio delle porte standard non cifrate (`80` HTTP, `21` FTP, `23` Telnet) per segnalare il transito di dati in chiaro.
* **Rilevamento Port Scan (Logica Stateful):** Utilizzo di strutture dati in memoria per tracciare il numero di porte uniche contattate da un singolo IP. Se viene superata la soglia impostata (Default: 10), scatta un alert critico.
* **SIEM-Ready Logging:** Esportazione automatica degli alert in formato JSON strutturato con timestamp e livelli di severity (`MEDIUM` / `HIGH`).

## 🛠️ Requisiti Tecnici

Il progetto richiede Python 3.x e la libreria `Scapy`.

```bash
pip install scapy

```

> ⚠️ **Nota sui permessi:** Per mettere l'interfaccia di rete in modalità promiscua e intercettare i pacchetti a basso livello, il sistema operativo richiede privilegi di amministratore.

## 💻 Come Utilizzarlo

1. Clona la repository ed entra nella cartella del progetto.
2. Avvia lo script con i privilegi elevati:

```bash
# Su Linux / macOS
sudo python sniffer.py

# Su Windows (Esegui il prompt dei comandi o PowerShell come Amministratore)
python sniffer.py

```

### Come simulare gli allarmi (Testing)

* **Per testare il rilevamento del traffico non cifrato:** Esegui una richiesta HTTP standard da un altro terminale:
```bash
curl [http://neverssl.com](http://neverssl.com)

```


* **Per testare il Port Scan:** Esegui una scansione automatizzata (es. usando Nmap verso il tuo host) oppure effettua connessioni rapide verso porte distinte.

## 📊 Struttura dei Log (Output JSON)

Gli alert vengono scritti in tempo reale nel file `security_alerts.json`. Ogni evento segue una struttura standardizzata:

```json
{
  "timestamp": "2026-06-06 21:50:12",
  "severity": "MEDIUM",
  "alert_type": "INSECURE_PROTOCOL",
  "details": {
    "src_ip": "192.168.1.15",
    "dst_ip": "1.1.1.1",
    "port": 80,
    "protocol": "HTTP"
  }
}

```

## 📈 Possibili Sviluppi 

* [ ] Introduzione del multi-threading per evitare la perdita di pacchetti su reti ad alto traffico.
* [ ] Integrazione di regole di detection avanzate basate sul formato standard **Sigma** o regole **Snort**.
* [ ] Analisi dei DNS query log per identificare tentativi di connessione a domini malevoli (DGA/C2).

---

Sviluppato a scopo didattico e di portfolio per il mondo della Cybersecurity.

```
