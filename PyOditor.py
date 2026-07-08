# -*- coding: utf-8 -*-
import socket
import threading
import requests
import datetime
import ssl
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# Verrou pour l'affichage propre dans la console (multi-thread)
print_lock = threading.Lock()

# Configuration du bareme de notation pour les headers HTTP (Total = 10 points)
SECURITY_HEADERS = {
    "Strict-Transport-Security": {"points": 2.5, "desc": "Protection HTTPS (HSTS)"},
    "Content-Security-Policy": {"points": 2.5, "desc": "Protection contre les injections XSS (CSP)"},
    "X-Frame-Options": {"points": 2.0, "desc": "Protection contre le Clickjacking"},
    "X-Content-Type-Options": {"points": 1.5, "desc": "Protection contre le MIME-sniffing"},
    "Referrer-Policy": {"points": 1.5, "desc": "Gestion du partage d'origine (Referrer)"}
}

def clean_target(user_input):
    """
    Extrait le FQDN/Nom d'hote propre a partir d'une entree utilisateur 
    qui peut etre une URL complete ou un nom de domaine brut.
    """
    input_str = user_input.strip()
    # Si l'utilisateur n'a pas mis de scheme (http/https), urlparse ne fonctionne pas correctement.
    # On ajoute temporairement un scheme fictif pour forcer le parsing correct.
    if not input_str.startswith(("http://", "https://")):
        parsed = urlparse(f"http://{input_str}")
    else:
        parsed = urlparse(input_str)
        
    # On recupere le hostname (ex: scanme.nmap.org)
    hostname = parsed.hostname
    
    # Au cas ou urlparse echoue (entree malformee), on retourne l'entree de base nettoyee
    return hostname if hostname else input_str

def scan_port(target_ip, port, timeout=2.0):
    """Scane un port TCP et determine son etat"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        
        status = "FILTRE / ERREUR"
        if result == 0:
            status = "OUVERT"
        elif result in [11, 10061, 111]:
            status = "FERME"
        elif result == 10035:
            status = "FILTRE (WSAEWOULDBLOCK)"
            
        sock.close()
        return status
    except socket.timeout:
        return "FILTRE (Timeout)"
    except Exception:
        return "ERREUR"

def check_tls_cert(hostname):
    """Verifie la validite et la date d'expiration du certificat TLS"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
        not_after_str = cert.get('notAfter')
        expiry_date = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
        remaining_days = (expiry_date - datetime.datetime.utcnow()).days
        
        issuer = dict(x[0] for x in cert.get('issuer'))
        issuer_name = issuer.get('commonName', issuer.get('organizationName', 'Inconnu'))
        
        return {
            "success": True,
            "issuer": issuer_name,
            "expiry_date": expiry_date.strftime('%Y-%m-%d %H:%M:%S UTC'),
            "remaining_days": remaining_days,
            "status": "VALIDE" if remaining_days > 0 else "EXPIRE"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def analyze_http_headers(user_input):
    """Analyse les en-tetes de securite HTTP (tente HTTPS, bascule en HTTP si echec)"""
    # Si c'est deja une URL complete, on la teste telle quelle
    if user_input.startswith(("http://", "https://")):
        urls_to_try = [user_input]
    else:
        # Sinon on genere les deux versions classiques
        urls_to_try = [f"https://{user_input}", f"http://{user_input}"]
        
    response = None
    error_msg = ""
    
    for target_url in urls_to_try:
        try:
            response = requests.head(target_url, timeout=4, allow_redirects=True)
            user_input = target_url
            break
        except Exception as e:
            error_msg = str(e)
            continue

    if response is None:
        return {"success": False, "url": user_input, "error": f"Connexion impossible : {error_msg}"}
        
    try:
        headers = response.headers
        results = {}
        score = 0.0
        
        for header, info in SECURITY_HEADERS.items():
            header_match = next((h for h in headers if h.lower() == header.lower()), None)
            if header_match:
                results[header] = {"present": True, "value": headers[header_match], "points": info["points"]}
                score += info["points"]
            else:
                results[header] = {"present": False, "value": None, "points": 0.0}
        return {"success": True, "url": user_input, "score": score, "details": results}
    except Exception as e:
        return {"success": False, "url": user_input, "error": str(e)}

def generate_reports(original_input, hostname, ip_address, port_results, http_results, tls_results, date_str):
    """Genere les rapports consolides en Markdown et HTML"""
    clean_name = hostname.replace('.', '_')
    
    # ---- 1. GENERATION DU RAPPORT MARKDOWN ----
    md_filename = f"rapport_audit_{clean_name}.md"
    with open(md_filename, "w", encoding="utf-8") as f:
        f.write(f"# Rapport d'Audit de Securite Automatise\n\n")
        f.write(f"**Date de l'audit :** {date_str}\n")
        f.write(f"**Saisie utilisateur :** {original_input}\n")
        f.write(f"**Cible detectee (Nom d'hote) :** {hostname} ({ip_address})\n\n")
        
        # Section TLS
        f.write(f"## 1. Verification du Certificat TLS\n\n")
        if tls_results and tls_results.get("success"):
            f.write(f"**Statut du certificat :** {tls_results['status']}\n")
            f.write(f"**Autorite de certification (CA) :** {tls_results['issuer']}\n")
            f.write(f"**Date d'expiration :** {tls_results['expiry_date']}\n")
            f.write(f"**Jours restants avant expiration :** {tls_results['remaining_days']} jours\n\n")
        else:
            msg = tls_results.get("error", "Pas de port 443 ouvert ou non supporte") if tls_results else "Non execute"
            f.write(f"Impossible de verifier le certificat TLS sur le port 443. Motif : {msg}\n\n")
        
        # Section Ports
        f.write(f"## 2. Scan de Ports TCP\n\n")
        f.write(f"| Port | Etat |\n| :--- | :--- |\n")
        for port, status in sorted(port_results.items()):
            f.write(f"| {port} | {status} |\n")
            
        # Section HTTP
        f.write(f"\n## 3. Analyse des En-tetes de Securite HTTP\n\n")
        if http_results and http_results.get("success"):
            f.write(f"**URL analysee :** {http_results['url']}\n")
            f.write(f"**Score Global :** {http_results['score']:.1f} / 10.0\n\n")
            f.write(f"| En-tete | Statut | Points | Valeur / Description |\n| :--- | :--- | :--- | :--- |\n")
            for header, detail in http_results["details"].items():
                status_txt = "[Present]" if detail["present"] else "[Manquant]"
                val_txt = detail["value"] if detail["present"] else SECURITY_HEADERS[header]["desc"]
                f.write(f"| {header} | {status_txt} | +{detail['points']} pts | {val_txt} |\n")
        else:
            msg = http_results.get("error", "Non specifie") if http_results else "Non execute"
            f.write(f"L'analyse HTTP n'a pas pu etre effectuee ou a ete ignoree. Motif : {msg}\n")
            
    # ---- 2. GENERATION DU RAPPORT HTML ----
    html_filename = f"rapport_audit_{clean_name}.html"
    with open(html_filename, "w", encoding="utf-8") as f:
        css = """
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background-color: #f4f6f9; color: #333; }
        h1 { color: #2c3e50; border-bottom: 3px solid #34495e; padding-bottom: 12px; }
        h2 { color: #2980b9; margin-top: 40px; border-left: 5px solid #2980b9; padding-left: 10px; }
        .meta { background-color: #ebf5fb; padding: 15px; border-radius: 5px; font-size: 1.1em; color: #2c3e50; line-height: 1.5; }
        table { border-collapse: collapse; width: 100%; margin-top: 15px; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        th, td { border: 1px solid #dddddd; text-align: left; padding: 12px; }
        th { background-color: #34495e; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .badge { padding: 5px 10px; border-radius: 4px; font-weight: bold; font-size: 0.85em; text-transform: uppercase; }
        .open { background-color: #2ecc71; color: white; }
        .closed { background-color: #e74c3c; color: white; }
        .filtered { background-color: #f1c40f; color: #2c3e50; }
        .score-box { font-size: 1.4em; font-weight: bold; padding: 15px; background: #fff; border: 2px solid #2980b9; display: inline-block; border-radius: 5px; margin: 15px 0; }
        .info-block { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); line-height: 1.6; }
        """
        f.write(f"<!DOCTYPE html>\n<html>\n<head>\n<meta charset='utf-8'>\n<title>Rapport d'Audit - {hostname}</title>\n<style>{css}</style>\n</head>\n<body>")
        f.write(f"<h1>Rapport d'Audit de Securite</h1>")
        f.write(f"<div class='meta'><strong>Date de l'audit :</strong> {date_str} <br> <strong>Saisie initiale :</strong> {original_input} <br> <strong>Nom d'hote extrait :</strong> {hostname} ({ip_address})</div>")
        
        # Section 1 : TLS
        f.write(f"<h2>1. Verification du Certificat TLS</h2>")
        if tls_results and tls_results.get("success"):
            cl_status = "open" if tls_results["status"] == "VALIDE" else "closed"
            f.write(f"<div class='info-block'>")
            f.write(f"<strong>Statut de validite :</strong> <span class='badge {cl_status}'>{tls_results['status']}</span><br>")
            f.write(f"<strong>Autorite d'emission (CA) :</strong> {tls_results['issuer']}<br>")
            f.write(f"<strong>Date d'expiration :</strong> {tls_results['expiry_date']}<br>")
            f.write(f"<strong>Temps restant :</strong> {tls_results['remaining_days']} jours")
            f.write(f"</div>")
        else:
            msg = tls_results.get("error", "Non disponible") if tls_results else "Non execute"
            f.write(f"<p style='color:#e74c3c;'>Impossible d'analyser le certificat TLS (Port 443 ferme ou injoignable). Motif : {msg}</p>")

        # Section 2 : Ports
        f.write(f"<h2>2. Scan de Ports TCP</h2>\n<table>\n<tr><th>Port</th><th>Etat</th></tr>")
        for port, status in sorted(port_results.items()):
            cl = "filtered"
            if "OUVERT" in status: cl = "open"
            elif "FERME" in status: cl = "closed"
            f.write(f"<tr><td><strong>{port}</strong></td><td><span class='badge {cl}'>{status}</span></td></tr>")
        f.write(f"</table>")
        
        # Section 3 : HTTP
        f.write(f"<h2>3. Analyse des En-tetes HTTP de Securite</h2>")
        if http_results and http_results.get("success"):
            f.write(f"<p><strong>URL scannee :</strong> <a href='{http_results['url']}' target='_blank'>{http_results['url']}</a></p>")
            f.write(f"<div class='score-box'>Score Global de Bonne Pratique : {http_results['score']:.1f} / 10.0</div>")
            f.write(f"<table>\n<tr><th>En-tete</th><th>Statut</th><th>Contribution</th><th>Valeur detectee / Description</th></tr>")
            for header, detail in http_results["details"].items():
                st_cl = "open" if detail["present"] else "closed"
                st_txt = "Present" if detail["present"] else "Manquant"
                vl = f"<code>{detail['value']}</code>" if detail["present"] else SECURITY_HEADERS[header]["desc"]
                f.write(f"<tr><td><strong>{header}</strong></td><td><span class='badge {st_cl}'>{st_txt}</span></td><td>+{detail['points']} pts</td><td>{vl}</td></tr>")
            f.write(f"</table>")
        else:
            msg = http_results.get("error", "Inconnue") if http_results else "Non execute"
            f.write(f"<p style='color:#e74c3c;'>L'analyse HTTP n'a pas pu etre effectuee. Motif : {msg}</p>")
            
        f.write(f"</body>\n</html>")
        
    return md_filename, html_filename

def main():
    print("-" * 60)
    print("      AUDITEUR DE SECURITE UNIFIE & RAPPORT (MD/HTML)")
    print("-" * 60)
    
    user_input = input("Entrez la cible (URL, IP ou FQDN, ex: https://scanme.nmap.org/index.html) : ").strip()
    if not user_input:
        print("[-] Cible invalide.")
        return
        
    # Isolation magique du nom d'hote pour socket/TLS
    hostname = clean_target(user_input)
    
    try:
        target_ip = socket.gethostbyname(hostname)
        print(f"[*] Cible resolue : {hostname} -> Adresse IP : {target_ip}")
    except Exception:
        print(f"[-] Impossible de resoudre le nom d'hote extrait : '{hostname}'")
        return
        
    try:
        start_port = int(input("Port de debut du scan (ex: 1) : "))
        end_port = int(input("Port de fin du scan (ex: 100) : "))
    except ValueError:
        print("[-] Ports invalides.")
        return
        
    # Module : TLS / SSL (Port 443 utilise le nom d'hote propre)
    print("\n[*] Verification du certificat TLS (Port 443)...")
    tls_results = check_tls_cert(hostname)
    if tls_results["success"]:
        print(f"  [+] Certificat : {tls_results['status']} (Expire dans {tls_results['remaining_days']} jours)")
    else:
        print(f"  [-] Erreur TLS / Port 443 non sécurisé ou injoignable")

    # Module : Analyse HTTP (Utilise la saisie de l'utilisateur pour tester l'URL exacte demandee)
    print("[*] Analyse des en-tetes HTTP en cours...")
    http_results = analyze_http_headers(user_input)
    
    # Module : Scan de ports multi-thread
    print(f"[*] Scan des ports {start_port} a {end_port} sur {target_ip}...")
    port_results = {}
    
    def worker(port):
        status = scan_port(target_ip, port)
        with print_lock:
            port_results[port] = status
            if status == "OUVERT":
                print(f"  [+] Port {port:<5} : \033[92m{status}\033[0m")
                
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(worker, port)
            
    # Consolidation et ecriture des rapports
    print("\n[*] Compilation des resultats et ecriture des rapports...")
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    md_file, html_file = generate_reports(user_input, hostname, target_ip, port_results, http_results, tls_results, now_str)
    
    print("-" * 60)
    print(f" [OK] Fin de l'audit ! Rapports generes :")
    print(f"      Rapport Markdown : {md_file}")
    print(f"      Rapport HTML     : {html_file}")
    print("-" * 60)

if __name__ == '__main__':
    main()
