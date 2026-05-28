from mitmproxy import http
import json, redis, uuid

r = redis.Redis(host='redis', port=6379, db=0)

class ProxyScanner:
    def response(self, flow: http.HTTPFlow):
        data = {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "body": flow.request.get_text(),
            "response_body": flow.response.get_text() if flow.response else "",
            "response_headers": dict(flow.response.headers) if flow.response else {},
            "status_code": flow.response.status_code if flow.response else None,
        }
        r.lpush("proxy_flows", json.dumps(data, default=str))

addons = [ProxyScanner()]
