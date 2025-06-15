import subprocess
import requests

def is_wordpress_site(url):
    if not url.startswith("http"):
        url = "http://" + url

    print("[+] Vérification avec option 1 : analyse du code source avec curl...")
    try:
        response = subprocess.check_output(["curl", "-s", url], stderr=subprocess.DEVNULL).decode()
        keywords = ["wordpress", "wp-content/themes/", "wp-content/plugins/"]
        if any(keyword in response.lower() for keyword in keywords):
            return "✔️ Oui - détecté via code source"
    except Exception:
        pass

    print("[+] Vérification avec option 2 : test de fichiers WordPress communs...")
    common_files = ["wp-login.php", "wp-config.php"]
    for file in common_files:
        try:
            r = requests.get(url.rstrip("/") + "/" + file, timeout=5)
            if r.status_code == 200 and "WordPress" in r.text:
                return f"✔️ Oui - détecté via présence de {file}"
        except:
            continue

    print("[+] Vérification avec option 3 : scan d’arborescence via dirb...")
    try:
        result = subprocess.check_output(["dirb", url, "/usr/share/dirb/wordlists/common.txt", "-o", "/tmp/dirb_result.txt"], stderr=subprocess.DEVNULL)
        with open("/tmp/dirb_result.txt", "r") as f:
            content = f.read()
            wordpress_dirs = ["wp-config.php", "wp-admin/", "wp-includes/", "wp-content/"]
            if any(item in content for item in wordpress_dirs):
                return "✔️ Oui - détecté via dirb"
    except Exception:
        pass

    return "❌ Non - WordPress non détecté"


#******************
resultat=is_wordpress_site("https://www.whitehouse.gov/")
print(resultat)