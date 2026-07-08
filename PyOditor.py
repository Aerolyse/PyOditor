import socket
import threading
import requests
import datetime
import ssl
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# Lock for clean console output during multi-threaded port scanning
print_lock = threading.Lock()

# Security headers scoring configuration (Total = 10 points)
SECURITY_HEADERS = {
    "Strict-Transport-Security": {"points": 2.5, "desc": "HTTPS Protection (HSTS)"},
    "Content-Security-Policy": {"points": 2.5, "desc": "XSS Injection Protection (CSP)"},
    "X-Frame-Options": {"points": 2.0, "desc": "Clickjacking Protection"},
    "X-Content-Type-Options": {"points": 1.5, "desc": "MIME-sniffing Protection"},
    "Referrer-Policy": {"points": 1.5, "desc": "Origin sharing policy (Referrer)"}
}

def clean_target(user_input):
    """Extracts the clean FQDN/Hostname from a raw URL string or raw domain."""
    input_str = user_input.strip()
    if not input_str.startswith(("http://", "https://")):
        parsed = urlparse(f"http://{input_str}")
    else:
        parsed = urlparse(input_str)
    hostname = parsed.hostname
    return hostname if hostname else input_str

def scan_port(target_ip, port, timeout=2.0):
    """Scans a single TCP port and returns its status."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        
        status = "FILTERED / ERROR"
        if result == 0:
            status = "OPEN"
        elif result in [11, 10061, 111]:
            status = "CLOSED"
        elif result == 10035:
            status = "FILTERED (WSAEWOULDBLOCK)"
            
        sock.close()
        return status
    except socket.timeout:
        return "FILTERED (Timeout)"
    except Exception:
        return "ERROR"

def check_tls_cert(hostname):
    """Checks TLS certificate metadata and remaining valid days."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
        not_after_str = cert.get('notAfter')
        expiry_date = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
        remaining_days = (expiry_date - datetime.datetime.utcnow()).days
        
        issuer = dict(x[0] for x in cert.get('issuer'))
        issuer_name = issuer.get('commonName', issuer.get('organizationName', 'Unknown'))
        
        return {
            "success": True,
            "issuer": issuer_name,
            "expiry_date": expiry_date.strftime('%Y-%m-%d %H:%M:%S UTC'),
            "remaining_days": remaining_days,
            "status": "VALID" if remaining_days > 0 else "EXPIRED"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def analyze_http_headers(user_input):
    """Analyzes security headers (tries HTTPS first, falls back to HTTP)."""
    if user_input.startswith(("http://", "https://")):
        urls_to_try = [user_input]
    else:
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
        return {"success": False, "url": user_input, "error": f"Connection failed: {error_msg}"}
        
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
    """Generates localized Markdown and HTML audit reports."""
    clean_name = hostname.replace('.', '_')
    
    # ---- 1. MARKDOWN GENERATION ----
    md_filename = f"rapport_audit_{clean_name}.md"
    with open(md_filename, "w", encoding="utf-8") as f:
        f.write(f"# Automated Security Audit Report\n\n")
        f.write(f"**Audit Date:** {date_str}\n")
        f.write(f"**User Input:** {original_input}\n")
        f.write(f"**Target Hostname:** {hostname} ({ip_address})\n\n")
        
        f.write(f"## 1. TLS Certificate Verification\n\n")
        if tls_results and tls_results.get("success"):
            f.write(f"**Status:** {tls_results['status']}\n")
            f.write(f"**Issuer CA:** {tls_results['issuer']}\n")
            f.write(f"**Expiration Date:** {tls_results['expiry_date']}\n")
            f.write(f"**Time Remaining:** {tls_results['remaining_days']} days\n\n")
        else:
            msg = tls_results.get("error", "Port 443 closed or unsupported") if tls_results else "Skipped"
            f.write(f"Could not verify TLS certificate. Reason: {msg}\n\n")
        
        f.write(f"## 2. TCP Port Scan\n\n")
        f.write(f"| Port | Status |\n| :--- | :--- |\n")
        for port, status in sorted(port_results.items()):
            f.write(f"| {port} | {status} |\n")
            
        f.write(f"\n## 3. HTTP Security Headers Analysis\n\n")
        if http_results and http_results.get("success"):
            f.write(f"**Target URL:** {http_results['url']}\n")
            f.write(f"**Overall Compliance Score:** {http_results['score']:.1f} / 10.0\n\n")
            f.write(f"| Header | Status | Impact | Value / Description |\n| :--- | :--- | :--- | :--- |\n")
            for header, detail in http_results["details"].items():
                status_txt = "[Present]" if detail["present"] else "[Missing]"
                val_txt = detail["value"] if detail["present"] else SECURITY_HEADERS[header]["desc"]
                f.write(f"| {header} | {status_txt} | +{detail['points']} pts | {val_txt} |\n")
        else:
            msg = http_results.get("error", "Unknown") if http_results else "Skipped"
            f.write(f"HTTP check could not complete. Reason: {msg}\n")
            
    # ---- 2. HTML GENERATION ----
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
        f.write(f"<!DOCTYPE html>\n<html>\n<head>\n<meta charset='utf-8'>\n<title>Audit Report - {hostname}</title>\n<style>{css}</style>\n</head>\n<body>")
        f.write(f"<h1>Security Audit Report</h1>")
        f.write(f"<div class='meta'><strong>Audit Date:</strong> {date_str} <br> <strong>User Input:</strong> {original_input} <br> <strong>Resolved Host:</strong> {hostname} ({ip_address})</div>")
        
        f.write(f"<h2>1. TLS Certificate Verification</h2>")
        if tls_results and tls_results.get("success"):
            cl_status = "open" if tls_results["status"] == "VALID" else "closed"
            f.write(f"<div class='info-block'>")
            f.write(f"<strong>Status:</strong> <span class='badge {cl_status}'>{tls_results['status']}</span><br>")
            f.write(f"<strong>Issuer Authority (CA):</strong> {tls_results['issuer']}<br>")
            f.write(f"<strong>Expiration Timeline:</strong> {tls_results['expiry_date']}<br>")
            f.write(f"<strong>Time Left:</strong> {tls_results['remaining_days']} days")
            f.write(f"</div>")
        else:
            msg = tls_results.get("error", "Unavailable") if tls_results else "Skipped"
            f.write(f"<p style='color:#e74c3c;'>TLS verification unavailable (Port 443 timed out or closed). Reason: {msg}</p>")

        f.write(f"<h2>2. TCP Port Scan</h2>\n<table>\n<tr><th>Port</th><th>Status</th></tr>")
        for port, status in sorted(port_results.items()):
            cl = "filtered"
            if "OPEN" in status: cl = "open"
            elif "CLOSED" in status: cl = "closed"
            f.write(f"<tr><td><strong>{port}</strong></td><td><span class='badge {cl}'>{status}</span></td></tr>")
        f.write(f"</table>")
        
        f.write(f"<h2>3. HTTP Security Headers Analysis</h2>")
        if http_results and http_results.get("success"):
            f.write(f"<p><strong>Inspected Endpoint:</strong> <a href='{http_results['url']}' target='_blank'>{http_results['url']}</a></p>")
            f.write(f"<div class='score-box'>Compliance Score: {http_results['score']:.1f} / 10.0</div>")
            f.write(f"<table>\n<tr><th>Header</th><th>Status</th><th>Contribution</th><th>Detected Value / Description</th></tr>")
            for header, detail in http_results["details"].items():
                st_cl = "open" if detail["present"] else "closed"
                st_txt = "Present" if detail["present"] else "Missing"
                vl = f"<code>{detail['value']}</code>" if detail["present"] else SECURITY_HEADERS[header]["desc"]
                f.write(f"<tr><td><strong>{header}</strong></td><td><span class='badge {st_cl}'>{st_txt}</span></td><td>+{detail['points']} pts</td><td>{vl}</td></tr>")
            f.write(f"</table>")
        else:
            msg = http_results.get("error", "Unknown") if http_results else "Skipped"
            f.write(f"<p style='color:#e74c3c;'>HTTP evaluation skipped. Reason: {msg}</p>")
            
        f.write(f"</body>\n</html>")
        
    return md_filename, html_filename

def main():
    print("-" * 60)
    print("                PyOditor - Multi-Target Edition")
    print("-" * 60)
    
    raw_input = input("Enter targets (separated by commas, e.g., github.com, 1.1.1.1) :\n> ").strip()
    if not raw_input:
        print("[-] Invalid input.")
        return
        
    # Splitting and cleaning up the inputs into individual elements
    targets = [t.strip() for t in raw_input.split(",") if t.strip()]
    if not targets:
        print("[-] No valid targets discovered.")
        return
        
    try:
        start_port = int(input("\n[Config] Start Port (e.g., 1): "))
        end_port = int(input("[Config] End Port (e.g., 100): "))
    except ValueError:
        print("[-] Invalid ports specified.")
        return

    # Loop to process every item sequentially
    for target in targets:
        print("\n" + "=" * 60)
        print(f" Processing Target: {target}")
        print("=" * 60)
        
        hostname = clean_target(target)
        try:
            target_ip = socket.gethostbyname(hostname)
            print(f"[*] Target resolved: {hostname} -> IP: {target_ip}")
        except Exception:
            print(f"[-] Could not resolve network host for raw input: '{target}' (Skipping)")
            continue
            
        print("[*] Verifying TLS Certificate context...")
        tls_results = check_tls_cert(hostname)
        if tls_results["success"]:
            print(f"  [+] Cert Status: {tls_results['status']} ({tls_results['remaining_days']} days remaining)")
        else:
            print(f"  [-] TLS Handshake failed or port 443 closed")

        print("[*] Scraping application HTTP Headers...")
        http_results = analyze_http_headers(target)
        if http_results["success"]:
            print(f"  [+] Headers checked. Score: {http_results['score']}/10")
            
        print(f"[*] Multithreaded TCP scanner firing up for ports {start_port} to {end_port}...")
        port_results = {}
        
        def worker(port):
            status = scan_port(target_ip, port)
            with print_lock:
                port_results[port] = status
                if status == "OPEN":
                    print(f"  [+] Alert - Port {port:<5} : {status}")
                    
        with ThreadPoolExecutor(max_workers=100) as executor:
            for port in range(start_port, end_port + 1):
                executor.submit(worker, port)
                
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        md_file, html_file = generate_reports(target, hostname, target_ip, port_results, http_results, tls_results, now_str)
        
        print(f"[✔] Reports generated successfully for {hostname}:")
        print(f"    -> {md_file}")
        print(f"    -> {html_file}")

    print("\n" + "-" * 60)
    print(" [OK] Bulk audit queue execution completely done.")
    print("-" * 60)

if __name__ == '__main__':
    main()
