import whois, requests, json

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return [{"type":"WHOIS","severity":"info","url":domain,"description":f"Registrar: {w.registrar}, Expires: {w.expiration_date}"}]
    except: return []

def shodan_info(domain):
    # Требуется SHODAN_API_KEY в env
    import os
    key = os.getenv("SHODAN_API_KEY")
    if not key: return []
    try:
        ip = requests.get(f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={key}").json().get(domain)
        if ip:
            info = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}").json()
            return [{"type":"Shodan","severity":"info","url":domain,"description":f"Open ports: {info.get('ports',[])}"}]
    except: return []
    return []

def hunter_search(domain):
    # HUNTER_API_KEY
    import os
    key = os.getenv("HUNTER_API_KEY")
    if not key: return []
    try:
        resp = requests.get(f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}")
        data = resp.json()
        emails = data.get('data',{}).get('emails',[])
        return [{"type":"Hunter.io","severity":"info","url":domain,"description":f"Found {len(emails)} email addresses"}]
    except: return []
