import requests
import subprocess

def is_prestashop_site(url):
    if not url.startswith("http"):
        url = "http://" + url

    headers = {'User-Agent': 'Mozilla/5.0'}

    print("[+] Vérification avec option 1 : analyse du code source avec curl...")
    try:
        response = subprocess.check_output(["curl", "-s", url], stderr=subprocess.DEVNULL).decode()
        keywords = [
            "prestashop",
            "/themes/",
            "/modules/",
            "prestashop.js",
            "Powered by PrestaShop",
            "content=\"PrestaShop\"",
            "var prestashop ="
        ]
        if any(keyword.lower() in response.lower() for keyword in keywords):
            return "✔️ Oui - détecté via code source"
    except Exception:
        pass

    print("[+] Vérification avec option 2 : analyse des cookies HTTP...")
    try:
        r = requests.get(url, headers=headers, timeout=5)
        for cookie in r.cookies:
            if 'PrestaShop' in cookie.name:
                return "✔️ Oui - détecté via cookie HTTP"
    except Exception:
        pass

    print("[+] Vérification avec option 3 : analyse des headers HTTP...")
    try:
        r = requests.head(url, headers=headers, timeout=5)
        if 'prestashop' in str(r.headers).lower():
            return "✔️ Oui - détecté via header HTTP"
    except Exception:
        pass

    print("[+] Vérification avec option 4 : test de pages spécifiques PrestaShop...")
    common_paths = [
        "index.php?controller=authentication",
        "index.php?controller=cart",
        "index.php?controller=product",
        "modules/"
    ]
    for path in common_paths:
        try:
            test_url = url.rstrip("/") + "/" + path
            r = requests.get(test_url, headers=headers, timeout=5)
            if ("prestashop" in r.text.lower() or "connexion" in r.text.lower()) and r.status_code == 200:
                return f"✔️ Oui - détecté via la page {path}"
        except Exception:
            continue

    print("[+] Vérification avec option 5 : scan d’arborescence via dirb...")
    try:
        result = subprocess.check_output(
            ["dirb", url, "/usr/share/dirb/wordlists/common.txt", "-o", "/tmp/dirb_result.txt"],
            stderr=subprocess.DEVNULL
        )
        with open("/tmp/dirb_result.txt", "r") as f:
            content = f.read()
            prestashop_dirs = ["modules/", "themes/", "admin", "prestashop.js"]
            if any(item in content for item in prestashop_dirs):
                return "✔️ Oui - détecté via dirb"
    except Exception:
        pass

    return "❌ Non - PrestaShop non détecté"

# Exemple d'utilisation
resultat = is_prestashop_site("https://www.frezalnumerique.fr/")
print(resultat)
