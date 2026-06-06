import re

# Il database delle firme crittografiche basato su Regex standard industriali
DIZIONARIO_HASH = {
    "MD5": {
        "regex": r"^[0-9a-fA-F]{32}$",
        "info": "Algoritmo legacy (32 caratteri esadecimali). Molto comune, vulnerabile a collisioni."
    },
    "SHA-1": {
        "regex": r"^[0-9a-fA-F]{40}$",
        "info": "Standard deprecato (40 caratteri esadecimali). Usato in vecchi sistemi e Git."
    },
    "SHA-256": {
        "regex": r"^[0-9a-fA-F]{64}$",
        "info": "Standard attuale sicuro (64 caratteri esadecimali). Usato in protocolli web e Blockchain."
    },
    "SHA-512": {
        "regex": r"^[0-9a-fA-F]{128}$",
        "info": "Algoritmo ad alta sicurezza della famiglia SHA-2 (128 caratteri esadecimali)."
    },
    "NTLM / LM (Windows)": {
        "regex": r"^[0-9a-fA-F]{32}$",
        "info": "Hash di autenticazione locale/dominio Microsoft Windows (SAM database e Active Directory)."
    },
    "MySQL 4.1+": {
        "regex": r"^\*[0-9a-fA-F]{40}$",
        "info": "Formato di hashing utilizzato dai server database MySQL e MariaDB (inizia con *)."
    },
    "bcrypt": {
        "regex": r"^\$2[axy]\$[0-9]{2}\$[./A-Za-z0-9]{53}$",
        "info": "Algoritmo sicuro basato su Blowfish con salt adattivo (standard Linux e moderni framework web)."
    },
    "md5(wordpress) / phpass": {
        "regex": r"^\$P\$[./A-Za-z0-9]{31}$",
        "info": "Formato specifico utilizzato dal CMS WordPress per proteggere le password nel database."
    },
    "Cisco Type 7": {
        "regex": r"^[0-9]{2}[0-9a-fA-F]+$",
        "info": "Cifratura debole utilizzata nei file di configurazione dei router Cisco (facilmente invertibile)."
    }
}

def analizza_hash(hash_string):
    hash_string = hash_string.strip()
    match_trovati = []
    
    for nome_algoritmo, regole in DIZIONARIO_HASH.items():
        if re.match(regole["regex"], hash_string):
            match_trovati.append((nome_algoritmo, regole["info"]))
            
    return match_trovati

def main():
    print("=" * 75)
    print("      🔏 PURE HASH IDENTIFIER - HIGH-SPEED CRYTOGRAPHIC ENGINE      ")
    print("=" * 75)
    
    hash_utente = input("\n[?] Inserisci l'hash da identificare: ").strip()
    
    if not hash_utente:
        print("[-] Input vuoto. Uscita.")
        return
        
    risultati = analizza_hash(hash_utente)
    
    if risultati:
        print(f"\n[*] Analisi strutturale completata. Rilevato/i {len(risultati)} possibile/i candidato/i:\n")
        for algoritmo, descrizione in risultati:
            print(f" 🎯 [TIPO]: \033[1;36m{algoritmo}\033[0m")
            print(f"    └── ℹ️ Dettagli: {descrizione}\n")
    else:
        print("\n[-] Nessun algoritmo corrispondente trovato nel database delle firme.")
        
    print("=" * 75)

if __name__ == "__main__":
    main()
