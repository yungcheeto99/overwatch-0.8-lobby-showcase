"""Project-owned local TLS certificate and public Windows trust export.

Reuse the project's existing key pair. Only the public leaf is exported for
trust installation; no CA key or upstream PFX is imported or distributed.
"""
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import ssl

from .bootstrap import DEFAULT_CERT, DEFAULT_KEY, generate_development_certificate


DEFAULT_PUBLIC = DEFAULT_CERT.with_suffix(".cer")
DEFAULT_PROFILE = DEFAULT_CERT.parent / "local-certificate.json"


def prepare_project_certificate(cert=DEFAULT_CERT, key=DEFAULT_KEY,
                                public=DEFAULT_PUBLIC, profile=DEFAULT_PROFILE):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    cert, key, public, profile = map(Path, (cert, key, public, profile))
    if not cert.exists() or not key.exists():
        generate_development_certificate(cert, key)
    leaf = x509.load_pem_x509_certificate(cert.read_bytes())
    private = serialization.load_pem_private_key(key.read_bytes(), password=None)
    certificate_key = leaf.public_key()
    if (not isinstance(private, rsa.RSAPrivateKey) or private.key_size != 2048
            or not isinstance(certificate_key, rsa.RSAPublicKey)
            or private.public_key().public_numbers() != certificate_key.public_numbers()):
        raise ValueError("The project TLS certificate and RSA-2048 private key do not match")
    common_names = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        constraints = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as error:
        raise ValueError("Project certificate requires loopback SAN and non-CA constraints") from error
    if (leaf.subject != leaf.issuer or len(common_names) != 1 or common_names[0].value != "127.0.0.1"
            or constraints.ca or ipaddress.ip_address("127.0.0.1") not in names.get_values_for_type(x509.IPAddress)):
        raise ValueError("Expected the project's self-signed, non-CA certificate for 127.0.0.1")
    now = datetime.now(timezone.utc)
    if not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc:
        raise ValueError("The project certificate is not currently valid; existing files were preserved")
    leaf.verify_directly_issued_by(leaf)
    der = leaf.public_bytes(serialization.Encoding.DER)
    description = {"subject": leaf.subject.rfc4514_string(), "issuer": leaf.issuer.rfc4514_string(),
                   "sha256": leaf.fingerprint(hashes.SHA256()).hex(),
                   "thumbprint": leaf.fingerprint(hashes.SHA1()).hex().upper(),
                   "not_before": leaf.not_valid_before_utc.isoformat(),
                   "not_after": leaf.not_valid_after_utc.isoformat(),
                   "is_ca": False, "trust_store": "CurrentUser/Root", "private_key_exported": False}
    public.parent.mkdir(parents=True, exist_ok=True)
    if public.exists() and public.read_bytes() != der:
        raise ValueError("The existing public trust export belongs to another certificate; files were preserved")
    if not public.exists():
        with public.open("xb") as stream:
            stream.write(der)
    profile.parent.mkdir(parents=True, exist_ok=True)
    contents = json.dumps(description, indent=2) + "\n"
    if not profile.exists() or profile.read_text(encoding="utf-8") != contents:
        profile.write_text(contents, encoding="utf-8")
    return description


def certificate_is_windows_trusted(cert=DEFAULT_CERT):
    """Check exact public DER membership, not whether the game's verifier accepts it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    if not hasattr(ssl, "enum_certificates"):
        return False
    der = x509.load_pem_x509_certificate(Path(cert).read_bytes()).public_bytes(serialization.Encoding.DER)
    return any(data == der and encoding == "x509_asn" for data, encoding, _trust in ssl.enum_certificates("ROOT"))
