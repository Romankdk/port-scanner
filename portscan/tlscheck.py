"""TLS/HTTPS checks: certificate validity, expiry, self-signed certs and outdated protocol versions."""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
import time
from typing import Optional

# Ports where TLS is spoken from the first byte.
TLS_PORTS = {443, 465, 636, 990, 993, 995, 5986, 8443}

EXPIRY_WARNING_DAYS = 30


def _insecure_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def is_tls(ip: str, port: int, timeout: float) -> bool:
    """True if the port completes a TLS handshake."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with _insecure_context().wrap_socket(s):
                return True
    except (OSError, ssl.SSLError):
        return False


def _decode_cert(der: bytes) -> dict:
    """Decode a DER certificate with the standard library (uses a CPython internal; best effort)."""
    path = ""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
            path = f.name
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:
        return {}
    finally:
        if path:
            os.unlink(path)


def _name(rdns) -> str:
    """Turn ((('commonName', 'x'),), ...) into 'CN=x, O=y'."""
    short = {"commonName": "CN", "organizationName": "O", "countryName": "C"}
    parts = []
    for rdn in rdns or ():
        for key, value in rdn:
            if key in short:
                parts.append(f"{short[key]}={value}")
    return ", ".join(parts)


def _accepts(ip: str, port: int, version: ssl.TLSVersion, server_name: Optional[str], timeout: float) -> Optional[bool]:
    """Does the server accept this exact protocol version? None if our TLS library can't test it."""
    ctx = _insecure_context()
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, ssl.SSLError):
        return None
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        ctx.set_ciphers("ALL")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=server_name):
                return True
    except ssl.SSLError:
        return False
    except OSError:
        return False


def check(ip: str, port: int, server_name: Optional[str] = None, timeout: float = 3.0) -> dict:
    """Inspect a TLS service. Returns details plus a list of [risk, issue] findings."""
    info: dict = {"version": "", "cipher": "", "subject": "", "issuer": "", "not_after": "",
                  "days_left": None, "self_signed": False, "verified": False, "verify_error": "",
                  "legacy_protocols": [], "issues": []}
    issues = info["issues"]

    # 1. Handshake without verification so we can always see the certificate.
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with _insecure_context().wrap_socket(s, server_hostname=server_name) as t:
                info["version"] = t.version() or ""
                info["cipher"] = (t.cipher() or ("",))[0]
                der = t.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as e:
        info["error"] = f"TLS handshake failed: {e}"
        return info

    cert = _decode_cert(der) if der else {}
    info["subject"] = _name(cert.get("subject"))
    info["issuer"] = _name(cert.get("issuer"))
    if cert.get("notAfter"):
        info["not_after"] = cert["notAfter"]
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        info["days_left"] = int((expires - time.time()) // 86400)
    if cert and cert.get("subject") == cert.get("issuer"):
        info["self_signed"] = True

    # 2. Full verification against the system's trusted CAs (and hostname, when we have one).
    ctx = ssl.create_default_context()
    ctx.check_hostname = bool(server_name)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=server_name):
                info["verified"] = True
    except ssl.SSLCertVerificationError as e:
        info["verify_error"] = e.verify_message or str(e)
        if "self signed" in info["verify_error"] or "self-signed" in info["verify_error"]:
            info["self_signed"] = True
    except (OSError, ssl.SSLError) as e:
        # A timeout or reset says nothing about the certificate; don't report it as untrusted.
        info["verify_skipped"] = str(e)

    # 3. Outdated protocol versions.
    for label, attr in (("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1")):
        if _accepts(ip, port, getattr(ssl.TLSVersion, attr), server_name, timeout):
            info["legacy_protocols"].append(label)

    # Findings. Keep the wording stable so scan comparisons don't flag day-to-day changes.
    days = info["days_left"]
    if days is not None and days < 0:
        issues.append(["high", "Certificate has expired"])
    elif days is not None and days < EXPIRY_WARNING_DAYS:
        issues.append(["medium", f"Certificate expires within {EXPIRY_WARNING_DAYS} days"])
    if info["self_signed"]:
        issues.append(["medium", "Self-signed certificate (browsers will warn)"])
    elif not info["verified"] and info["verify_error"] and not (days is not None and days < 0):
        issues.append(["medium", f"Certificate not trusted: {info['verify_error']}"])
    if info["version"] in ("TLSv1", "TLSv1.1"):
        issues.append(["high", f"Negotiates outdated {info['version']} by default"])
    for proto in info["legacy_protocols"]:
        issues.append(["medium", f"Still accepts outdated {proto}"])
    return info
