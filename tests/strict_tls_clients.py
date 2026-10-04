"""Hermes-matched clients against the real generated-CA CONNECT fixture."""

import socket
import ssl
import sys
import urllib.request

import httpx


assert sys.version_info[:3] == (3, 13, 5), "requires Hermes Python 3.13.5"
assert httpx.__version__ == "0.28.1", "requires Hermes HTTPX 0.28.1"
proxy, ca_file = sys.argv[1:]
context = ssl.create_default_context(cafile=ca_file)
assert context.verify_flags & ssl.VERIFY_X509_STRICT
assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
url = "https://allowed.test/plain"

opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"https": proxy}),
    urllib.request.HTTPSHandler(context=context),
)
with opener.open(url, timeout=10) as response:
    assert response.status == 200
    assert b"data: /plain" in response.read()

# Match the cutover reproduction: HTTPX constructs its own default strict
# context from the CA filename. Do not change verify flags or hostname checks.
response = httpx.get(url, proxy=proxy, verify=ca_file, timeout=10, trust_env=False)
assert response.status_code == 200 and "data: /plain" in response.text
with httpx.Client(proxy=proxy, verify=context, timeout=10, trust_env=False) as client:
    assert client.get(url).status_code == 200
    assert client.get("https://allowed.test/not-granted").status_code == 403
    assert client.get(url).status_code == 200

try:
    httpx.get(url, proxy=proxy, timeout=10, trust_env=False)
except httpx.ConnectError as error:
    assert "CERTIFICATE_VERIFY_FAILED" in str(error)
else:
    raise AssertionError("untrusted interception CA was accepted")

host, port = proxy.removeprefix("http://").rsplit(":", 1)
with socket.create_connection((host, int(port)), timeout=10) as tunnel:
    tunnel.sendall(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
    headers = b""
    while not headers.endswith(b"\r\n\r\n"):
        chunk = tunnel.recv(1)
        assert chunk and len(headers) < 4096
        headers += chunk
    assert headers.startswith(b"HTTP/1.1 200")
    try:
        context.wrap_socket(tunnel, server_hostname="wrong.test")
    except ssl.SSLCertVerificationError:
        pass
    else:
        raise AssertionError("hostname checking was bypassed")

assert context.verify_flags & ssl.VERIFY_X509_STRICT
assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
print("PASS: Python 3.13.5 urllib and HTTPX 0.28.1 strict CONNECT trust, reuse and denials")
