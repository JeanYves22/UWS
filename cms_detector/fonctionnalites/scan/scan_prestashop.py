import requests
import ssl
import socket
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

COMMON_PATHS = [
    "admin/", "admin123/", "admin-dev/", "install/", "config/settings.inc.php",
    ".git/", ".env", ".svn/", "backup.zip", "db.sql", "dump.sql", "robots.txt", "phpinfo.php"
]

MODULES_PATH = "modules/"
HEADERS_SECURITY_CHECKS = [
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"
]

audit_result = {
    "site": "",
    "files_exposed": [],
    "modules": [],
    "security_headers": {},
    "ssl_info": {},
    "robots_issues": [],
    "cves": []
}
def detect_prestashop_version(base_url):
    print("\n[+] Tentative de détection de la version PrestaShop...")
    candidates = []

    try:
        r = requests.get(base_url, timeout=5)
        html = r.text

        # Méthodes courantes
        if "PrestaShop™" in html or "PrestaShop" in html:
            import re
            versions = re.findall(r"PrestaShop[\s™]*(?:v)?(\d+\.\d+\.\d+)", html)
            if versions:
                candidates += versions

        # Meta generator
        soup = BeautifulSoup(html, 'html.parser')
        meta = soup.find("meta", attrs={"name": "generator"})
        if meta and "PrestaShop" in meta.get("content", ""):
            content = meta["content"]
            parts = content.split()
            for p in parts:
                if p.count('.') == 2:
                    candidates.append(p)

    except Exception as e:
        print(f"[!] Erreur de détection version : {e}")

    # Nettoyage et affichage
    unique_versions = list(set(candidates))
    if unique_versions:
        version = unique_versions[0]
        print(f"[+] Version détectée : {version}")
        return version
    else:
        print("[-] Version PrestaShop non détectée automatiquement")
        return None
def get_host_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = cert.get("issuer", [["", ""]])[0][1]
                expiry = cert.get("notAfter", "")
                print(f"[+] Certificat SSL valide - expire le : {expiry}")
                audit_result["ssl_info"] = {
                    "issuer": issuer,
                    "expires": expiry
                }
    except Exception as e:
        print(f"[!] SSL non disponible ou mal configuré : {e}")
        audit_result["ssl_info"]["error"] = str(e)

def check_common_paths(base_url):
    print("\n[+] Vérification des fichiers/répertoires sensibles...")
    for path in COMMON_PATHS:
        full_url = urljoin(base_url, path)
        try:
            r = requests.head(full_url, timeout=5, allow_redirects=True)
            if r.status_code in [200, 403]:
                print(f"   [!] {path} accessible (code {r.status_code})")
                audit_result["files_exposed"].append(path)
        except:
            continue

def check_modules(base_url):
    print("\n[+] Vérification des modules...")
    modules_url = urljoin(base_url, MODULES_PATH)
    try:
        r = requests.get(modules_url, timeout=5)
        if r.status_code == 200 and "Index of" in r.text:
            print("   [!] Listing des modules activé !")
            soup = BeautifulSoup(r.text, 'html.parser')
            links = soup.find_all('a')
            for link in links:
                if link.text not in ['../', '/']:
                    module = link.text.strip()
                    print(f"      - Module : {module}")
                    audit_result["modules"].append(module)
    except:
        print("   [-] Impossible de vérifier les modules.")

def check_headers(base_url):
    print("\n[+] Analyse des en-têtes de sécurité...")
    try:
        r = requests.get(base_url, timeout=10)
        for h in HEADERS_SECURITY_CHECKS:
            if h in r.headers:
                audit_result["security_headers"][h] = True
                print(f"   [+] {h} présent")
            else:
                audit_result["security_headers"][h] = False
                print(f"   [-] {h} manquant")
    except Exception as e:
        print(f"[!] Erreur headers : {e}")

def check_robots_txt(base_url):
    print("\n[+] Analyse de robots.txt...")
    try:
        r = requests.get(urljoin(base_url, "robots.txt"), timeout=5)
        if r.status_code == 200 and r.text:
            lines = r.text.lower().splitlines()
            for line in lines:
                if "admin" in line or "install" in line or ".php" in line:
                    print(f"   [!] robots.txt contient : {line}")
                    audit_result["robots_issues"].append(line.strip())
        else:
            print("   [-] Aucun robots.txt détecté")
    except:
        print("   [-] robots.txt inaccessible")

def check_redirect_http_to_https(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        try:
            http_url = "http://" + parsed.netloc
            r = requests.get(http_url, timeout=5, allow_redirects=True)
            if r.url.startswith("https://"):
                print(f"[+] Redirection HTTP vers HTTPS active")
            else:
                print(f"[-] Pas de redirection HTTPS détectée")
        except Exception as e:
            print(f"[!] Test HTTPS échoué : {e}")

def search_cves(version):
    print(f"\n[+] Recherche des CVEs pour PrestaShop {version}...")
    try:
        res = requests.get(f"https://cve.circl.lu/api/search/prestashop/{version}", timeout=10)
        if res.status_code == 200:
            data = res.json()
            for cve in data.get("data", []):
                print(f"   [CVE] {cve['id']} : {cve['summary'][:80]}...")
                audit_result["cves"].append({
                    "id": cve["id"],
                    "summary": cve["summary"]
                })
        else:
            print("   [-] Aucune CVE trouvée ou erreur d'accès à l'API")
    except Exception as e:
        print(f"[!] Erreur API CVE : {e}")

def save_report():
    with open("rapport_audit.json", "w", encoding="utf-8") as f:
        json.dump(audit_result, f, indent=4, ensure_ascii=False)
    print("\n📄 Rapport exporté : rapport_audit.json")

def main():
    print("=== Audit sécurité PrestaShop + CVE + JSON ===")
    target = input("URL du site (ex: https://exemple.com/) : ").strip()
    version = detect_prestashop_version(target)
    if version:
     search_cves(version)
    else:
        print("   ↳ CVEs non recherchées car version inconnue")
    if not target.startswith("http"):
        target = "http://" + target
    audit_result["site"] = target

    version = input("Version de PrestaShop (ex: 1.7.8.0) : ").strip()
    if version:
        search_cves(version)

    print("\n[*] Début de l’audit...\n")
    check_redirect_http_to_https(target)
    check_common_paths(target)
    check_modules(target)
    check_headers(target)
    check_robots_txt(target)

    parsed = urlparse(target)
    get_host_ssl_info(parsed.netloc)

    save_report()
    print("\n✅ Audit terminé.")

if _name_ == "_main_":
    main()