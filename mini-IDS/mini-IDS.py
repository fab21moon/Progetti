import json
from datetime import datetime
from scapy.all import sniff, IP, TCP

# Dizionario globale per il Port Scan
storico_connessioni = {}
SOGLIA_PORT_SCAN = 10

def salva_alert_json(tipo_allarme, dettagli):
    """
    Prende i dettagli di un allarme, aggiunge un timestamp preciso 
    e scrive l'evento in un file JSON in modalità 'append' (aggiunta).
    """
    payload = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": "HIGH" if tipo_allarme == "PORT_SCAN" else "MEDIUM",
        "alert_type": tipo_allarme,
        "details": dettagli
    }
    
    # Scriviamo l'allarme nel file (una riga per ogni evento, formato JSON Lines)
    with open("security_alerts.json", "a") as f:
        f.write(json.dumps(payload) + "\n")

def analizza_pacchetto(packet):
    global storico_connessioni
    
    if packet.haslayer(IP):
        ip_sorgente = packet[IP].src
        ip_destinazione = packet[IP].dst
        
        if packet.haslayer(TCP):
            porta_dest = packet[TCP].dport
            
            # 1. REGOLA PROTOCOLLI NON SICURI
            if porta_dest in [80, 21, 23]:
                protocolli = {80: "HTTP", 21: "FTP", 23: "Telnet"}
                nome_proto = protocolli[porta_dest]
                
                msg = f"Rilevato traffico non cifrato {nome_proto} verso {ip_destinazione}:{porta_dest}"
                print(f"[⚠️ SECURITY ALERT] {msg}")
                
                # Salviamo l'evento nel JSON
                salva_alert_json("INSECURE_PROTOCOL", {"src_ip": ip_sorgente, "dst_ip": ip_destinazione, "port": porta_dest, "protocol": nome_proto})

            # 2. REGOLA PORT SCAN
            if ip_sorgente not in storico_connessioni:
                storico_connessioni[ip_sorgente] = set()
            
            storico_connessioni[ip_sorgente].add(porta_dest)
            quante_porte = len(storico_connessioni[ip_sorgente])
            
            if quante_porte > SOGLIA_PORT_SCAN:
                msg = f"L'IP {ip_sorgente} ha scansionato {quante_porte} porte distinte."
                print(f"[🚨 CRITICAL ALERT] {msg}")
                
                # Salviamo l'evento nel JSON
                salva_alert_json("PORT_SCAN", {"attacker_ip": ip_sorgente, "ports_scanned": quante_porte})

def main():
    print("[*] mini-IDS Professionale avviato... Monitoraggio attivo.")
    print("[*] Gli alert verranno salvati in 'security_alerts.json'.\n")
    sniff(prn=analizza_pacchetto)

if __name__ == "__main__":
    main()
    
    # Rimuoviamo il count così lo sniffer gira all'infinito finché non lo stoppi tu
    sniff(prn=analizza_pacchetto)

if __name__ == "__main__":
    main()
