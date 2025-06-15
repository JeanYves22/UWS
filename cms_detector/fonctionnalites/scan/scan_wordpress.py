import subprocess
import json

def scan_wordpress_site(url: str, api_token: str) -> dict:
    """
    Scanne un site WordPress avec WPScan et retourne les vulnérabilités détectées.

    Args:
        url (str): Lien vers le site WordPress à scanner.
        api_token (str): Token WPScan API.

    Returns:
        dict: Résultat structuré du scan (vulnérabilités, utilisateurs, plugins vulnérables...).
    """
    try:
        print(f"[+] Scan de {url} en cours...")
        result = subprocess.run([
            "wpscan",
            "--url", url,
            "--enumerate", "u,vp,vt",
            "--api-token", api_token,
            "--format", "json"
        ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)

        output = result.stdout
        data = json.loads(output)

        summary = {
            "target_url": url,
            "version": data.get("version", {}).get("number", "inconnue"),
            "vulnerable_version": data.get("version", {}).get("vulnerable", False),
            "plugins_vulnérables": [],
            "thèmes_vulnérables": [],
            "utilisateurs": [],
        }

        # Plugins
        if "plugins" in data:
            for plugin, details in data["plugins"].items():
                if details.get("vulnerabilities"):
                    summary["plugins_vulnérables"].append({
                        "nom": plugin,
                        "version": details.get("version"),
                        "vulnérabilités": details["vulnerabilities"]
                    })

        # Thèmes
        if "themes" in data:
            for theme, details in data["themes"].items():
                if details.get("vulnerabilities"):
                    summary["thèmes_vulnérables"].append({
                        "nom": theme,
                        "version": details.get("version"),
                        "vulnérabilités": details["vulnerabilities"]
                    })

        # Utilisateurs
        if "users" in data:
            for user in data["users"]:
                summary["utilisateurs"].append(user.get("username"))

        return summary

    except subprocess.CalledProcessError as e:
        print("[!] Erreur d’exécution de WPScan.")
        return {"erreur": "Échec du scan WPScan"}
    except json.JSONDecodeError:
        print("[!] Impossible de décoder la sortie JSON.")
        return {"erreur": "Sortie non valide de WPScan"}