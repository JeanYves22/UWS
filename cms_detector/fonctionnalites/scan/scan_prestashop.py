import requests
import socket
import ssl
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def detect_prestashop_version(base_url):
    try:
        r = requests.get(base_url, timeout=5)
        html = r.text
        soup = BeautifulSoup(html, 'html.parser')

        # 1. Meta tag
        meta = soup.find("meta", attrs={"name": "generator"})
        if meta and "PrestaShop" in meta.get("content", ""):
            version = meta["content"].split()[-1].strip()
            return version

        # 2. Fallback regex
        import re
        match = re.search(r"PrestaShop(?:™)?[\s]*v?(\d+\.\d+\.\d+)", html)
        if match:
            return match.group(1)

    except:
        pass
    return None

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "expires": cert.get("notAfter", "")
                }
    except Exception as e:
        return {"error": str(e)}

def check_paths(base_url):
    sensitive = []
    paths = [
        "admin/", "admin-dev/", "install/", ".git/", ".env",
        "config/settings.inc.php", "phpinfo.php", "backup.zip", "robots.txt"
    ]
    for path in paths:
        try:
            r = requests.head(urljoin(base_url, path), timeout=5, allow_redirects=True)
            if r.status_code in [200, 403]:
                sensitive.append(path)
        except:
            continue
    return sensitive

def check_headers(base_url):
    headers_status = {}
    try:
        r = requests.get(base_url, timeout=5)
        headers = r.headers
        checks = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection"
        ]
        for h in checks:
            headers_status[h] = h in headers
    except:
        for h in checks:
            headers_status[h] = False
    return headers_status

def check_modules(base_url):
    modules = []
    try:
        r = requests.get(urljoin(base_url, "modules/"), timeout=5)
        if r.status_code == 200 and "Index of" in r.text:
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a"):
                if link.text not in ["/", "../"]:
                    modules.append(link.text.strip("/"))
    except:
        pass
    return modules

def check_robots(base_url):
    exposed = []
    try:
        r = requests.get(urljoin(base_url, "robots.txt"), timeout=5)
        if r.status_code == 200:
            for line in r.text.splitlines():
                if any(x in line.lower() for x in ["admin", "install", ".php"]):
                    exposed.append(line.strip())
    except:
        pass
    return exposed

def search_cves(version):
    try:
        r = requests.get(f"https://cve.circl.lu/api/search/prestashop/{version}", timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", [])
            return [{
                "id": cve.get("id"),
                "summary": cve.get("summary", "")[:120] + "..." if cve.get("summary") else ""
            } for cve in data]
    except:
        pass
    return []

def scan_prestashop_site(url: str) -> dict:
    print(f"[+] Audit de sécurité PrestaShop pour : {url}")

    result = {
        "target_url": url,
        "version": None,
        "fichiers_sensibles": [],
        "modules_detectés": [],
        "headers_sécurité": {},
        "certificat_ssl": {},
        "cves": [],
        "robots.txt": []
    }

    # Normalisation URL
    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)

    # Version
    version = detect_prestashop_version(url)
    result["version"] = version

    # SSL
    result["certificat_ssl"] = get_ssl_info(parsed.netloc)

    # Audit
    result["fichiers_sensibles"] = check_paths(url)
    result["headers_sécurité"] = check_headers(url)
    result["modules_detectés"] = check_modules(url)
    result["robots.txt"] = check_robots(url)

    if version:
        result["cves"] = search_cves(version)

    return result

# Exemple d’utilisation
if _name_ == "_main_":
    site = input("URL du site PrestaShop à scanner : ").strip()
    report = scan_prestashop_site(site)

    print("\n=== Résumé JSON ===")
    print(json.dumps(report, indent=4, ensure_ascii=False))

    # Export JSON
    with open("rapport_prestashop.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    print("\n📄 Rapport exporté : rapport_prestashop.json")