from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import re
import json
from http.client import HTTPSConnection
import os
from AI import summarize_security_scan


api_key = os.getenv("GOOGLE_API_KEY")


app = Flask(__name__, static_folder='static')
CORS(app)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({
            'url': '',
            'status': 'Error',
            'issues_found': -1,
            'message': 'No URL provided.'
        }), 400

    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'https://' + url  # Default to HTTPS for modern security

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    try:
        issues = []

        # HTTPS check
        if parsed_url.scheme != 'https':
            issues.append("URL does not use HTTPS")

        # SSL certificate validation and additional SSL checks
        if parsed_url.scheme == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        # Check certificate expiration
                        if 'notAfter' in cert:
                            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            if not_after < datetime.utcnow():
                                issues.append('SSL certificate has expired')
                        # Check weak cipher suites
                        if ssock.cipher()[1].startswith(('RC4', 'DES', '3DES')):
                            issues.append('Weak cipher suite detected')
                        # Check SSL/TLS protocol version
                        if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                            issues.append(f'Outdated TLS version: {ssock.version()}')
            except ssl.SSLError as ssl_err:
                return jsonify({
                    'url': url,
                    'status': 'Error',
                    'issues_found': -1,
                    'message': f"SSL certificate error: {ssl_err}"
                }), 400

        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers
        cookies = response.cookies
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Base headers
        required_headers = [
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'X-Frame-Options',
            'Referrer-Policy'
        ]
        for header in required_headers:
            if header.lower() not in headers_lower:
                issues.append(f"Missing security header: {header}")

        # Header values
        if headers_lower.get('x-content-type-options', '') != 'nosniff':
            issues.append('X-Content-Type-Options should be "nosniff"')

        hsts = headers_lower.get('strict-transport-security', '')
        if not hsts or 'max-age' not in hsts or 'max-age=0' in hsts:
            issues.append('Strict-Transport-Security missing or misconfigured')

        # Extra headers
        if 'permissions-policy' not in headers_lower:
            issues.append('Missing security header: Permissions-Policy')
        if 'feature-policy' not in headers_lower:
            issues.append('Missing (deprecated) Feature-Policy header')
        if 'x-xss-protection' not in headers_lower:
            issues.append('Missing deprecated X-XSS-Protection header')
        if 'cache-control' not in headers_lower:
            issues.append('Missing Cache-Control header')
        if 'pragma' not in headers_lower or 'expires' not in headers_lower:
            issues.append('Missing Pragma or Expires headers (caching issues)')
        if 'expect-ct' not in headers_lower:
            issues.append('Missing Expect-CT header')

        # Server info exposure
        if 'server' in headers_lower:
            issues.append('Server header is exposed')
        if 'x-powered-by' in headers_lower:
            issues.append('X-Powered-By header reveals backend technology')

        # Weak CSP values
        csp = headers_lower.get('content-security-policy', '')
        if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
            issues.append('Content-Security-Policy contains unsafe directives')

        # Cookie checks
        for cookie in cookies:
            # Secure flag check
            if not cookie.secure:
                issues.append(f'Cookie "{cookie.name}" missing Secure flag')

            # HttpOnly check
            cookie_rest_keys = {k.lower() for k in cookie._rest.keys()} if hasattr(cookie, '_rest') else set()
            if 'httponly' not in cookie_rest_keys:
                issues.append(f'Cookie "{cookie.name}" missing HttpOnly flag')

            # SameSite attribute check
            if not any(k.lower() == 'samesite' for k in cookie_rest_keys):
                issues.append(f'Cookie "{cookie.name}" missing SameSite attribute')

        # Dangerous HTTP methods
        try:
            options = requests.options(url, timeout=5)
            if 'Allow' in options.headers:
                allow_methods = options.headers['Allow'].upper().split(',')
                if any(m in ['PUT', 'DELETE', 'TRACE'] for m in allow_methods):
                    issues.append(f'HTTP methods PUT, DELETE, or TRACE are enabled')
        except Exception:
            pass

        # Optional path-based exposure checks (lightweight)
        for path in ['/admin', '/phpinfo.php', '/.git', '/.env', '/wp-admin', '/config', '/backup']:
            try:
                probe = requests.get(f"{url.rstrip('/')}{path}", timeout=5)
                if probe.status_code == 200:
                    issues.append(f'Exposed sensitive path: {path}')
            except Exception:
                continue

        # New Security Checks
        # 1. CORS Misconfiguration
        if 'access-control-allow-origin' in headers_lower:
            acao = headers_lower['access-control-allow-origin']
            if acao == '*' and 'access-control-allow-credentials' in headers_lower:
                issues.append('CORS misconfiguration: Wildcard ACAO with credentials allowed')

        # 2. JSON Content-Type Validation
        if 'content-type' in headers_lower and 'application/json' in headers_lower['content-type']:
            try:
                json.loads(response.text)
            except json.JSONDecodeError:
                issues.append('Invalid JSON in response with application/json Content-Type')

        # 3. Cross-Origin Resource Sharing Headers
        if 'access-control-allow-methods' in headers_lower:
            methods = [m.strip().upper() for m in headers_lower['access-control-allow-methods'].split(',')]
            if any(m in ['PUT', 'DELETE', 'PATCH'] for m in methods):
                issues.append('CORS allows unsafe methods: PUT, DELETE, or PATCH')

        # 4. Insecure Redirects
        if response.history:
            for redirect in response.history:
                if redirect.url.startswith('http://') and response.url.startswith('https://'):
                    issues.append('Insecure redirect from HTTP to HTTPS detected')

        # 5. Content Type Sniffing Risk
        if 'content-type' not in headers_lower:
            issues.append('Missing Content-Type header, risking MIME type sniffing')

        # 6. Clickjacking Protection
        if headers_lower.get('x-frame-options', '').lower() not in ['deny', 'sameorigin']:
            issues.append('X-Frame-Options misconfigured, vulnerable to clickjacking')

        # 7. Subresource Integrity (SRI)
        try:
            if '<script' in response.text.lower():
                if 'integrity' not in response.text.lower():
                    issues.append('External scripts detected without Subresource Integrity (SRI)')
        except Exception:
            pass

        # 8. Referrer Policy Misconfiguration
        if headers_lower.get('referrer-policy', '').lower() not in ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']:
            issues.append('Referrer-Policy misconfigured or unsafe')

        # 9. DNS Rebinding Risk
        try:
            ip = socket.gethostbyname(hostname)
            # Check for private or loopback IP ranges
            private_prefixes = ['127.', '0.', '192.168.', '10.', '172.16.']
            if any(ip.startswith(prefix) for prefix in private_prefixes):
                issues.append('DNS resolves to private or loopback IP, potential DNS rebinding risk')
        except socket.gaierror:
            pass

        # 10. HTTP/2 Support
        try:
            conn = HTTPSConnection(hostname, timeout=5)
            conn.request('GET', '/', headers={'Connection': 'Upgrade, HTTP2-Settings', 'Upgrade': 'h2c'})
            resp = conn.getresponse()
            if resp.status != 101:
                issues.append('HTTP/2 not supported, missing performance and security benefits')
        except Exception:
            pass

        # 11. Insecure WebSocket (Note: only heuristic, no real check done)
        try:
            ws_url = f"ws://{hostname}{parsed_url.path}"
            # WebSocket actual check skipped (needs ws client)
        except Exception:
            pass

        # 12. Directory Listing Exposure
        try:
            dir_probe = requests.get(f"{url.rstrip('/')}/", timeout=5)
            if 'Index of' in dir_probe.text or '<title>Index of' in dir_probe.text:
                issues.append('Directory listing enabled, exposing file structure')
        except Exception:
            pass

        # 13. Mixed Content
        if response.url.startswith('https://'):
            try:
                if 'http://' in response.text:
                    issues.append('Mixed content detected: HTTP resources on HTTPS page')
            except Exception:
                pass

        # 14. HTTP Public Key Pinning (HPKP)
        if 'public-key-pins' not in headers_lower:
            issues.append('Missing HTTP Public Key Pinning (HPKP) header (deprecated but relevant)')

        # 15. Cross-Origin Embedder Policy (COEP)
        if 'cross-origin-embedder-policy' not in headers_lower:
            issues.append('Missing Cross-Origin-Embedder-Policy (COEP) header')

        # 16. Cross-Origin Opener Policy (COOP)
        if 'cross-origin-opener-policy' not in headers_lower:
            issues.append('Missing Cross-Origin-Opener-Policy (COOP) header')

        # 17. Cross-Origin Resource Policy (CORP)
        if 'cross-origin-resource-policy' not in headers_lower:
            issues.append('Missing Cross-Origin-Resource-Policy (CORP) header')

        # 18. Open Redirect Vulnerability
        try:
            redirect_probe = requests.get(f"{url}?redirect=http://evil.com", timeout=5, allow_redirects=False)
            if redirect_probe.status_code in [301, 302, 303, 307, 308]:
                if 'evil.com' in redirect_probe.headers.get('location', ''):
                    issues.append('Potential open redirect vulnerability detected')
        except Exception:
            pass

        # 19. XML External Entity (XXE) Exposure
        try:
            xml_probe = requests.get(f"{url}/api.xml", headers={'Accept': 'application/xml'}, timeout=5)
            if xml_probe.status_code == 200 and 'xml' in xml_probe.text.lower():
                issues.append('XML endpoint exposed, potential XXE vulnerability')
        except Exception:
            pass

        # 20. Server Timing Header Exposure
        if 'server-timing' in headers_lower:
            issues.append('Server-Timing header exposed, may leak performance metrics')

        # 21. Basic SQL Injection Exposure
        try:
            sql_probe = requests.get(f"{url}?id=1'", timeout=5)
            if 'sql syntax' in sql_probe.text.lower() or 'mysql_error' in sql_probe.text.lower():
                issues.append('Potential SQL injection vulnerability detected')
        except Exception:
            pass

        # 22. Version Disclosure in Headers
        try:
            for header, value in headers.items():
                if isinstance(value, str) and re.search(r'\d+\.\d+\.\d+', value):
                    issues.append(f'Version information disclosed in header: {header}')
        except Exception:
            # Catch all regex-related or others
            pass

        # 23. ETag Header Privacy Risk
        if 'etag' in headers_lower:
            issues.append('ETag header present, may enable tracking or cache-based attacks')

        total_issues = len(issues)
        message_lines = [f"Issues found: {total_issues}"] + [f"    {issue}" for issue in issues]
        message = "\n".join(message_lines) if issues else "✅ Basic scan successful! All key security checks passed."

        score = max(0, 100 - total_issues * 3)
        score = min(score, 100)

        ai_summary = summarize_security_scan(message)

        return jsonify({
            'url': url,
            'status': 'OK',
            'issues_found': total_issues,
            'message': message,
            'score': score,
            'summary': ai_summary
        })

    except requests.exceptions.RequestException as e:
        return jsonify({
            'url': url,
            'status': 'Error',
            'issues_found': -1,
            'message': f"Failed to fetch URL: {str(e)}"
        }), 400
    except Exception as e:
        return jsonify({
            'url': url,
            'status': 'Error',
            'issues_found': -1,
            'message': f"Unexpected error: {str(e)}"
        }), 500


@app.route('/', defaults={'path': 'index.html'})
@app.route('/<path:path>')
def serve_frontend(path):
    return send_from_directory(app.static_folder, path)


if __name__ == '__main__':
    app.run(debug=True)
