import subprocess, json, re, requests, tempfile, os
from urllib.parse import urljoin

def subdomain_enum(domain):
    cmd = f"subfinder -d {domain} -silent; assetfinder --subs-only {domain}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    subs = list(set(proc.stdout.strip().splitlines()))
    return subs

def live_hosts(subs):
    if not subs: return []
    with open("/tmp/subs.txt", "w") as f:
        f.write("\n".join(subs))
    cmd = "httpx -l /tmp/subs.txt -silent -probe -title -tech-detect -status-code"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return [line for line in proc.stdout.splitlines() if line]

def nuclei_scan(hosts):
    if not hosts: return []
    with open("/tmp/live.txt", "w") as f:
        f.write("\n".join(hosts))
    cmd = "nuclei -l /tmp/live.txt -json -severity low,medium,high,critical -rate-limit 50"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
    findings = []
    for line in proc.stdout.splitlines():
        try:
            d = json.loads(line)
            findings.append({
                "type": d.get("template-id","unknown"),
                "severity": d.get("info",{}).get("severity","info"),
                "url": d.get("matched-at",""),
                "description": d.get("info",{}).get("description",""),
                "evidence": d.get("curl-command","")
            })
        except: pass
    return findings

def zap_scan(url):
    # ZAP должен быть доступен как демон (или через zap-cli)
    try:
        cmd = f"zap-cli quick-scan --self-contained --start-options '-config api.key=test' {url}"
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        # парсинг вывода упрощённый
        return [{"type":"ZAP Finding","severity":"medium","url":url,"description":"ZAP found potential issues"}]
    except:
        return []

def header_analysis(url):
    findings = []
    try:
        resp = requests.get(url, timeout=10)
        h = resp.headers
        if 'X-Frame-Options' not in h: findings.append({"type":"Missing X-Frame-Options","severity":"medium","url":url})
        if 'Content-Security-Policy' not in h: findings.append({"type":"Missing CSP","severity":"medium","url":url})
        if 'Strict-Transport-Security' not in h: findings.append({"type":"Missing HSTS","severity":"low","url":url})
    except: pass
    return findings

def tls_analysis(url):
    host = url.split("//")[-1].split("/")[0]
    cmd = f"testssl --json-pretty https://{host}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    # парсинг json-отчёта
    return []

def js_secrets_scan(url):
    findings = []
    try:
        resp = requests.get(url, timeout=10)
        js_files = re.findall(r'<script[^>]+src=["\'](.*?)["\']', resp.text)
        for js in js_files:
            full_url = urljoin(url, js)
            js_resp = requests.get(full_url)
            with tempfile.NamedTemporaryFile(delete=False, suffix='.js') as f:
                f.write(js_resp.content)
                f.flush()
                cmd = f"gitleaks detect --source {f.name} -v"
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if "leak" in proc.stdout.lower():
                    findings.append({"type":"Secret in JS","severity":"high","url":full_url})
                os.unlink(f.name)
    except: pass
    return findings

def sqlmap_scan(url):
    cmd = f"sqlmap -u {url} --batch --level=1 --risk=1 --crawl=2 --forms --random-agent"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
    if "is vulnerable" in proc.stdout:
        return [{"type":"SQL Injection","severity":"critical","url":url,"description":"SQLi detected"}]
    return []

def dalfox_xss(url):
    cmd = f"dalfox url {url} --silence --format json"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    try:
        data = json.loads(proc.stdout)
        return [{"type":"XSS","severity":"high","url":url,"description":"XSS found"}]
    except: return []

def command_injection_scan(url):
    cmd = f"commix --url {url} --batch"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    if "vulnerable" in proc.stdout.lower():
        return [{"type":"Command Injection","severity":"critical","url":url}]
    return []

def wpscan_scan(url):
    cmd = f"wpscan --url {url} --enumerate p --format json --no-banner"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
    return []
