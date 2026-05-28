from celery import Celery
import redis, json, logging
from .scanners import (
    subdomain_enum, live_hosts, nuclei_scan,
    header_analysis, tls_analysis, js_secrets_scan,
    sqlmap_scan, dalfox_xss, command_injection_scan,
    zap_scan, wpscan_scan
)
from .osint_tools import hunter_search, shodan_info, whois_lookup
from .injection_probes import process_proxy_task
from .knowledge_base import get_fix

celery = Celery('hamer_hunter', broker='redis://redis:6379/0', backend='redis://redis:6379/0')

@celery.task(bind=True)
def run_full_scan(self, url: str):
    results = []
    domain = url.split("//")[-1].split("/")[0]

    # OSINT
    results += whois_lookup(domain)
    results += shodan_info(domain)
    results += hunter_search(domain)

    # Разведка
    subs = subdomain_enum(domain)
    live = live_hosts(subs)
    if live:
        results += nuclei_scan(live)
        results += zap_scan(url)  # активный ZAP-скан основного URL
        results += sqlmap_scan(url)
        results += dalfox_xss(url)
        results += command_injection_scan(url)
        results += wpscan_scan(url)  # если WordPress

    # Пассивный анализ
    results += header_analysis(url)
    results += tls_analysis(url)
    results += js_secrets_scan(url)

    # Добавляем рекомендации по исправлению
    for r in results:
        r['fix'] = get_fix(r.get('type', ''))

    return results

# Фоновая задача – читает поток из прокси и проверяет инъекции
@celery.task
def consume_proxy_flows():
    r = redis.Redis(host='redis', port=6379, db=0)
    while True:
        _, flow_json = r.brpop("proxy_flows", timeout=5)
        if flow_json:
            findings = process_proxy_task(flow_json)
            if findings:
                r.publish("scan_results", json.dumps(findings, default=str))
