"""
Generate a self-signed TLS certificate for the Hub.
This allows the Minifra Secure Console (served over HTTPS) to connect
to the Hub over HTTPS without mixed-content browser errors.

The user only needs to accept the certificate warning once in their browser.
"""
import ipaddress
import os
import sys
from datetime import datetime, timedelta, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    print("Installing cryptography...")
    os.system(f"{sys.executable} -m pip install cryptography --quiet")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")
CERT_FILE = os.path.join(CERT_DIR, "cert.pem")
KEY_FILE  = os.path.join(CERT_DIR, "key.pem")
HUB_IP    = "192.168.1.109"


def generate():
    os.makedirs(CERT_DIR, exist_ok=True)

    print(f"Generating RSA 2048 key...")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MiniFra Security Ltd"),
        x509.NameAttribute(NameOID.COMMON_NAME, HUB_IP),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.IPv4Address(HUB_IP)),
                x509.DNSName("localhost"),
                x509.DNSName("minifra-hub"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"✓  Certificate:  {CERT_FILE}")
    print(f"✓  Private key:  {KEY_FILE}")
    print(f"")
    print(f"   Hub will serve HTTPS on https://{HUB_IP}:8080")
    print(f"   To trust in browser: visit https://{HUB_IP}:8080/health")
    print(f"   and click 'Advanced → Proceed anyway'")


if __name__ == "__main__":
    generate()
