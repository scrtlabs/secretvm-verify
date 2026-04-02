"""URL detection and VM endpoint fetching utilities."""

import html
import re

import requests

SECRET_VM_PORT = 29343


def is_vm_url(data: str) -> bool:
    """Detect whether a string is a VM URL rather than raw quote data."""
    s = data.strip()
    if s.startswith("https://") or s.startswith("http://"):
        return True
    return "." in s and " " not in s and "\n" not in s and len(s) < 256


def _vm_base_url(url: str) -> str:
    """Normalize a VM URL to https://host:port."""
    from urllib.parse import urlparse

    u = url.strip()
    if "://" not in u:
        u = f"https://{u}"
    parsed = urlparse(u)
    port = parsed.port or SECRET_VM_PORT
    return f"https://{parsed.hostname}:{port}"


def fetch_vm_endpoint(url: str, endpoint: str) -> str:
    """Fetch data from a VM endpoint."""
    base = _vm_base_url(url)
    resp = requests.get(f"{base}/{endpoint}", timeout=15, verify=True)
    resp.raise_for_status()
    return resp.text


def fetch_cpu_quote(url: str) -> str:
    """Fetch CPU quote from a VM."""
    return fetch_vm_endpoint(url, "cpu")


def fetch_gpu_quote(url: str) -> str:
    """Fetch GPU attestation from a VM."""
    return fetch_vm_endpoint(url, "gpu")


def fetch_docker_compose(url: str) -> str:
    """Fetch and clean docker-compose from a VM."""
    raw = fetch_vm_endpoint(url, "docker-compose")
    return _extract_docker_compose(raw)


def _extract_docker_compose(raw: str) -> str:
    """Extract YAML from an HTML-wrapped response."""
    text = raw.strip()
    m = re.search(r"<pre>(.*?)</pre>", text, re.DOTALL | re.IGNORECASE)
    if m:
        text = m.group(1)
    text = html.unescape(text)
    text = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", text)
    return text
