"""
ca_utils.py
-----------
Các hàm tiện ích cho hệ thống Certificate Authority (CA):
  - generate_key        : Tạo cặp khóa RSA
  - save_key            : Lưu private key ra file PEM
  - save_cert           : Lưu certificate ra file PEM
  - load_key            : Nạp private key từ file PEM
  - load_cert           : Nạp certificate từ file PEM
  - create_root_ca      : Tạo Root CA tự ký
  - create_intermediate_ca : Tạo Intermediate CA được ký bởi Root CA
  - issue_certificate   : Phát hành chứng chỉ end-entity
  - verify_certificate_chain : Xác minh chuỗi tin cậy
"""

import os
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Thư mục lưu chứng chỉ và khóa
CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")
os.makedirs(CERTS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Tạo & lưu / nạp khóa
# ---------------------------------------------------------------------------

def generate_key(key_size: int = 2048):
    """Tạo cặp khóa RSA với độ dài key_size bit."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )


def save_key(key, filename: str, password: bytes = None):
    """
    Lưu private key ra file PEM trong thư mục certs/.
    Nếu password != None thì mã hoá bằng AES-256-CBC.
    """
    path = os.path.join(CERTS_DIR, filename)
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption,
    )
    with open(path, "wb") as f:
        f.write(pem)
    print(f"[save_key] Đã lưu private key -> {path}")
    return path


def save_cert(cert, filename: str):
    """Lưu certificate ra file PEM trong thư mục certs/."""
    path = os.path.join(CERTS_DIR, filename)
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[save_cert] Đã lưu certificate -> {path}")
    return path


def load_key(filename: str, password: bytes = None):
    """Nạp private key từ file PEM trong thư mục certs/."""
    path = os.path.join(CERTS_DIR, filename)
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password, backend=default_backend())


def load_cert(filename: str):
    """Nạp certificate từ file PEM trong thư mục certs/."""
    path = os.path.join(CERTS_DIR, filename)
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


# ---------------------------------------------------------------------------
# Xây dựng Subject Name
# ---------------------------------------------------------------------------

def _build_name(common_name: str, org: str, country: str = "VN") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


# ---------------------------------------------------------------------------
# Tạo Root CA
# ---------------------------------------------------------------------------

def create_root_ca(subject_info: dict, valid_days: int = 3650):
    """
    Tạo Root CA tự ký (self-signed).

    subject_info = {
        "common_name": "...",
        "org": "...",
        "country": "VN",   # tuỳ chọn
    }

    Trả về (root_key, root_cert).
    File lưu: certs/root_ca.key, certs/root_ca.crt
    """
    key = generate_key(4096)
    name = _build_name(
        subject_info["common_name"],
        subject_info["org"],
        subject_info.get("country", "VN"),
    )

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)                     # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    save_key(key, "root_ca.key")
    save_cert(cert, "root_ca.crt")
    print("[create_root_ca] Root CA đã được tạo thành công.")
    return key, cert


# ---------------------------------------------------------------------------
# Tạo Intermediate CA
# ---------------------------------------------------------------------------

def create_intermediate_ca(subject_info: dict, root_key, root_cert, valid_days: int = 1825):
    """
    Tạo Intermediate CA được ký bởi Root CA.

    Trả về (inter_key, inter_cert).
    File lưu: certs/intermediate_ca.key, certs/intermediate_ca.crt
    """
    key = generate_key(2048)
    subject = _build_name(
        subject_info["common_name"],
        subject_info["org"],
        subject_info.get("country", "VN"),
    )

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    save_key(key, "intermediate_ca.key")
    save_cert(cert, "intermediate_ca.crt")
    print("[create_intermediate_ca] Intermediate CA đã được tạo thành công.")
    return key, cert


# ---------------------------------------------------------------------------
# Phát hành chứng chỉ end-entity
# ---------------------------------------------------------------------------

def issue_certificate(subject_info: dict, issuer_key, issuer_cert, valid_days: int = 365, san_dns: list = None):
    """
    Phát hành chứng chỉ end-entity (TLS server / client) được ký bởi Intermediate CA.

    subject_info = {
        "common_name": "...",
        "org": "...",
        "country": "VN",
    }
    san_dns : danh sách tên miền (Subject Alternative Name), e.g. ["example.com", "www.example.com"]

    Trả về (entity_key, entity_cert).
    File lưu: certs/<common_name>.key, certs/<common_name>.crt
    """
    key = generate_key(2048)
    subject = _build_name(
        subject_info["common_name"],
        subject_info["org"],
        subject_info.get("country", "VN"),
    )

    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
    )

    # Subject Alternative Names
    if san_dns:
        san_list = [x509.DNSName(d) for d in san_dns]
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    cert = builder.sign(issuer_key, hashes.SHA256(), default_backend())

    cn = subject_info["common_name"].replace(" ", "_")
    save_key(key, f"{cn}.key")
    save_cert(cert, f"{cn}.crt")
    print(f"[issue_certificate] Chứng chỉ cho '{subject_info['common_name']}' đã được cấp.")
    return key, cert


# ---------------------------------------------------------------------------
# Xác minh chuỗi chứng chỉ
# ---------------------------------------------------------------------------

def verify_certificate_chain(entity_cert, issuer_cert, root_cert) -> bool:
    """
    Kiểm tra chuỗi tin cậy:
      entity_cert  <-- ký bởi --> issuer_cert (Intermediate CA)
      issuer_cert  <-- ký bởi --> root_cert   (Root CA)

    Trả về True nếu hợp lệ, False nếu không.
    """
    try:
        # Kiểm tra entity_cert được ký bởi issuer_cert
        issuer_cert.public_key().verify(
            entity_cert.signature,
            entity_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            entity_cert.signature_hash_algorithm,
        )
        print("[verify] entity_cert <- intermediate_ca : HỢP LỆ ✓")

        # Kiểm tra issuer_cert được ký bởi root_cert
        root_cert.public_key().verify(
            issuer_cert.signature,
            issuer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            issuer_cert.signature_hash_algorithm,
        )
        print("[verify] intermediate_ca <- root_ca     : HỢP LỆ ✓")

        # Kiểm tra root_cert tự ký
        root_cert.public_key().verify(
            root_cert.signature,
            root_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            root_cert.signature_hash_algorithm,
        )
        print("[verify] root_ca (self-signed)           : HỢP LỆ ✓")

        print("[verify] Toàn bộ chuỗi chứng chỉ HỢP LỆ ✓")
        return True

    except Exception as exc:
        print(f"[verify] CHUỖI KHÔNG HỢP LỆ ✗ -- {exc}")
        return False
