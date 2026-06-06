# Modular Vulnerability Scanner & Recon Framework (Python / Live NIST API)

Un framework automatizzato di **Vulnerability Assessment** a riga di comando (CLI) sviluppato in Python. Il tool esegue una ricognizione attiva sui target specificati, identifica lo stato delle porte di trasporto (TCP Connect Scan), effettua il *Banner Grabbing* e correla in tempo reale le informazioni raccolte con le vulnerabilità note censite globalmente.

A differenza dei software di scansione statici, questo script si collega direttamente via API al database del governo americano **NVD (National Vulnerability Database) del NIST**, estraendo le ultime **CVE** (Common Vulnerabilities and Exposures) aggiornate in tempo reale.

## 🚀 Funzionalità Principali

* **TCP Port Scanner Nativo:** Sviluppato utilizzando esclusivamente la libreria standard `socket` di Python, senza dipendenze esterne pesanti.
* **Smart Banner Grabbing:** Intercettazione e pulizia delle stringhe di identificazione rilasciate dai servizi di rete (es. OpenSSH, Apache, ecc.).
* **Live Threat Intelligence Integration:** Connessione diretta alle API REST v2 del National Vulnerability Database (NVD) per cercare corrispondenze basate su keyword e versioni software.
* **Automated Markdown Reporting:** Generazione automatica di un report finale di audit formattato in Markdown (`report_[target].md`), strutturato in modo professionale e pronto per essere condiviso con il team di sviluppo o di management.
* **Robust CLI Parsing:** Gestione flessibile dei parametri di input tramite la libreria `argparse` (formato standard degli strumenti di sicurezza Linux).

## 🛠️ Requisiti Tecnici

Il progetto utilizza moduli nativi di Python, ad eccezione della libreria `requests` per la gestione delle chiamate API esterne.

```bash
pip install requests

```

## 💻 Come Utilizzarlo

Il tool richiede come parametro obbligatorio l'host target (`-t` o `--target`), che può essere un indirizzo IP o un dominio su cui si hanno i permessi di audit.

```bash
# Scansione del sistema locale
python scanner.py -t 127.0.0.1

# Scansione di un host specifico nella LAN
python scanner.py -t 192.168.1.50

```

### Parametri disponibili:

* `-h`, `--help`: Mostra la schermata di aiuto con la sintassi dei comandi.
* `-t TARGET`, `--target TARGET`: Specifica l'IP o il dominio dell'obiettivo.

## 📊 Esempio di Report Generato (`.md`)

Il file di output viene formattato automaticamente. Di seguito un esempio di come appare il file `report_127_0_0_1.md` quando viene rilevato un servizio con vulnerabilità note:

---

# 🛡️ Report di Vulnerability Assessment

**Target Analizzato:** `192.168.176.130`   
**Data Scansione:** 2026-06-06 17:24:05  

--- 

### 🚪 Porta 22 - APERTA
* **Banner Rilevato:** `SSH-2.0-OpenSSH_10.3p1 Debian-1`

#### 🚨 Vulnerabilità Critiche Identificate (NIST NVD):
* **CVE-2007-0726**
  * *Descrizione:* The SSH key generation process in OpenSSH in Apple Mac OS X 10.3.9 and 10.4 through 10.4.8 allows remote attackers to cause a denial of service by con...
* **CVE-2026-35385**
  * *Descrizione:* In OpenSSH before 10.3, a file downloaded by scp may be installed setuid or setgid, an outcome contrary to some users' expectations, if the download i...
* **CVE-2026-35386**
  * *Descrizione:* In OpenSSH before 10.3, command execution can occur via shell metacharacters in a username within a command line. This requires a scenario where the u...

---

## 📈 Possibili Sviluppi

* [ ] Implementazione del multi-threading per la scansione simultanea di interi range di rete (es. CIDR /24).
* [ ] Traduzione automatica della stringa di banner nel formato standardizzato **CPE (Common Platform Enumeration)** per una precisione di ricerca del 100%.
* [ ] Supporto alla scansione UDP avanzata.

---

Sviluppato a scopo didattico e come strumento di ricognizione automatizzata per attività di Ethical Hacking.

