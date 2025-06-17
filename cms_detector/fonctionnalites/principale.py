def detect_and_scan_cms(url: str):
    """
    Détecte le CMS (WordPress ou PrestaShop) d'un site, puis lance le scan approprié.

    Args:
        url (str): L'URL du site à analyser.

    Returns:
        dict: Résultat du scan ou message d'absence de CMS connu.
    """

    print(f"[+] Analyse de l'URL : {url}")

    from .detections.detection_wordpress import is_wordpress_site
    from .scan.scan_wordpress import scan_wordpress_site
    from .detections.detection_prestashop import is_prestashop_site
    from .scan.scan_prestashop import scan_prestashop

    # Étape 1 : Détection WordPress
    if is_wordpress_site(url) == "oui":
        print("[✔] WordPress détecté.")
        result = scan_wordpress_site(url)
        return {"cms": "wordpress", "resultat": result}

    # Étape 2 : Détection PrestaShop
    elif is_prestashop_site(url) == "oui":
        print("[✔] PrestaShop détecté.")
        result = scan_prestashop(url)
        return {"cms": "prestashop", "resultat": result}

    else:
        print("[✘] Aucun CMS connu détecté.")
        return {"cms": "inconnu", "message": "CMS non détecté ou non pris en charge"}