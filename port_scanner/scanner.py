import socket
import requests
import time
import argparse

def pulisci_banner(banner_testo):
    """Estrae una stringa pulita dal banner per l'interrogazione API."""
    banner_clean = banner_testo.replace("SSH-2.0-", "").replace("_", " ")
    parti = banner_clean.split()
    if len(parti) >= 2:
        return f"{parti[0]} {parti[1].split('p')[0]}"
    return banner_clean

def interroga_nvd_real(keyword):
    """Interroga il National Vulnerability Database (NVD) del NIST."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 3}
    
    try:
        risposta = requests.get(url, params=params, timeout=10)
        if risposta.status_code == 200:
            dati = risposta.json()
            if dati.get("totalResults", 0) == 0:
                return None
                
            vulnerabilita_trovate = []
            for vuln in dati.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                vulnerabilita_trovate.append({
                    "id": cve_data.get("id"),
                    "desc": cve_data.get("descriptions", [{}])[0].get("value", "Nessuna descrizione")[:150] + "..."
                })
            return vulnerabilita_trovate
    except Exception:
        return None
    return None

def scan_e_grab(target_host, porta):
    """Verifica se la porta è aperta e tenta il banner grabbing."""
    risultato = {"aperta": False, "banner": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        if s.connect_ex((target_host, porta)) == 0:
            risultato["aperta"] = True
            try:
                risultato["banner"] = s.recv(1024).decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                risultato["banner"] = "Porta aperta (Nessun banner spontaneo)"
    except Exception:
        pass
    finally:
        s.close()
    return risultato

def genera_report_markdown(target, risultati):
    """Prende i risultati e genera un report formattato in Markdown."""
    filename = f"report_{target.replace('.', '_')}.md"
    
    with open(filename, "w") as f:
        f.write(f"# 🛡️ Report di Vulnerability Assessment\n\n")
        f.write(f"**Target Analizzato:** `{target}`  \n")
        f.write(f"**Data Scansione:** {time.strftime('%Y-%m-%d %H:%M:%S')}  \n\n")
        f.write(f"--- \n\n")
        
        for r in risultati:
            f.write(f"### 🚪 Porta {r['porta']} - {r['stato']}\n")
            if r['banner']:
                f.write(f"* **Banner Rilevato:** `{r['banner']}`\n")
            
            if r['cve']:
                f.write(f"\n#### 🚨 Vulnerabilità Critiche Identificate (NIST NVD):\n")
                for cve in r['cve']:
                    f.write(f"* **{cve['id']}**\n")
                    f.write(f"  * *Descrizione:* {cve['desc']}\n")
            elif r['stato'] == "APERTA":
                f.write(f"\n✅ Nessuna CVE nota trovata nel primo screening per questa release.\n")
            f.write(f"\n\n")
            
    print(f"[*] Report salvato con successo in: '{filename}'")

def main():
    # Configurazione di argparse per gestire i parametri da terminale
    parser = argparse.ArgumentParser(description="Framework di Vulnerability Assessment in tempo reale connesso al NIST NVD.")
    parser.add_argument("-t", "--target", required=True, help="Indirizzo IP o Dominio del target da scansionare")
    args = parser.parse_args()
    
    # Lista delle porte standard da scansionare
    porte_comuni = [21, 22, 80, 443, 8080]
    report_data = []
    
    print(f"[*] Framework di Vulnerability Assessment avviato su: {args.target}")
    print("[*] Connessione live al NIST NVD attiva.\n")
    
    for porta in porte_comuni:
        esito = scan_e_grab(args.target, porta)
        
        if esito["aperta"]:
            print(f"[+] Porta {porta} [APERTA] -> Banner: {esito['banner']}")
            cve_trovate = None
            
            # Se abbiamo un banner reale, interroghiamo il NIST
            if "Porta aperta" not in esito["banner"] and esito["banner"]:
                keyword = pulisci_banner(esito['banner'])
                cve_trovate = interroga_nvd_real(keyword)
                
                if cve_trovate:
                    print(f"    🚨 Trovate vulnerabilità per '{keyword}'! Generazione dati...")
            
            # Salviamo i dati per il report finale
            report_data.append({
                "porta": porta,
                "stato": "APERTA",
                "banner": esito["banner"],
                "cve": cve_trovate
            })
            
            time.sleep(1) # Rispetto dei limiti della frequenza API
            
    # Alla fine dello scanning, se abbiamo trovato porte aperte, generiamo il report
    if report_data:
        print("\n[*] Generazione del report in corso...")
        genera_report_markdown(args.target, report_data)
    else:
        print("[-] Nessuna porta aperta rilevata. Report non generato.")

if __name__ == "__main__":
    main()
