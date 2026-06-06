# Pure Hash Identifier (Python / Regex Engine)

Un motore di identificazione crittografica ad alta velocità sviluppato in Python. Questo tool nasce per supportare le fasi iniziali di triage durante attività di Penetration Testing o CTF, permettendo all'analista di riconoscere istantaneamente la tipologia di un hash sconosciuto prima di passarlo a strumenti di cracking dedicati come *Hashcat* o *John the Ripper*.

## 🚀 Caratteristiche Principali

* **Zero Dipendenze:** Sviluppato utilizzando esclusivamente il modulo nativo `re` (Espressioni Regolari) di Python. Nessuna installazione o connessione di rete richiesta.
* **Database di Firme Esteso:** Riconoscimento accurato dei formati più diffusi nell'Information Security (Sistemi operativi, Database, CMS e apparati di rete).
* **Gestione delle Ambiguità:** Il tool identifica se una stringa geometrica può corrispondere a più algoritmi (es. la sovrapposizione strutturale tra MD5 e Windows NTLM), mostrando tutte le opzioni plausibili.

## 📊 Algoritmi Supportati

* **Sistemi Operativi:** Windows LM/NTLM, Linux `bcrypt`
* **Standard Globali:** MD5, SHA-1, SHA-256, SHA-512
* **Database & CMS:** MySQL 4.1+, WordPress (`phpass`)
* **Networking:** Cisco Type 7

## 💻 Installazione ed Uso

```bash
# Clona il progetto ed esegui lo script
python hash_id.py
```
## Esempio di Output
```bash
Plaintext
[?] Inserisci l'hash da identificare: 21232f297a57a5a743894a0e4a801fc3

[*] Analisi strutturale completata. Rilevato/i 2 possibile/i candidato/i:

 🎯 [TIPO]: MD5
    └── ℹ️ Dettagli: Algoritmo legacy (32 caratteri esadecimali). Molto comune, vulnerabile a collisioni.

 🎯 [TIPO]: NTLM / LM (Windows)
    └── ℹ️ Dettagli: Hash di autenticazione locale/dominio Microsoft Windows (SAM database e Active Directory).
```
---
Sviluppato come utility tool a riga di comando per attività di Ethical Hacking e Log Analysis.
