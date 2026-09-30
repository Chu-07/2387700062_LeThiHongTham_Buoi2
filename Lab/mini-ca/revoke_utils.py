"""
revoke_utils.py
---------------
Quản lý danh sách thu hồi chứng chỉ (Certificate Revocation List - CRL):
  - create_empty_crl       : Tạo CRL rỗng được ký bởi CA
  - revoke_certificate     : Thêm chứng chỉ vào CRL
  - check_revocation_status: Kiểm tra trạng thái thu hồi của một chứng chỉ
"""

import os
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")
CRL_PATH   = os.path.join(CERTS_DIR, "crl.pem")

os.makedirs(CERTS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Tạo CRL rỗng
# ---------------------------------------------------------------------------

def create_empty_crl(ca_key, ca_cert, next_update_days: int = 30) -> x509.CertificateRevocationList:
    """
    Tạo và lưu CRL rỗng (chưa thu hồi chứng chỉ nào).

    Tham số:
        ca_key           : Private key của CA dùng để ký CRL
        ca_cert          : Certificate của CA
        next_update_days : Số ngày trước khi CRL hết hạn

    Trả về đối tượng CRL đã ký.
    """
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=next_update_days))
    )

    crl = builder.sign(ca_key, hashes.SHA256(), default_backend())
    _save_crl(crl)
    print(f"[create_empty_crl] CRL rỗng đã được tạo -> {CRL_PATH}")
    return crl


# ---------------------------------------------------------------------------
# Thu hồi chứng chỉ
# ---------------------------------------------------------------------------

def revoke_certificate(
    cert_to_revoke: x509.Certificate,
    ca_key,
    ca_cert: x509.Certificate,
    reason: x509.ReasonFlags = x509.ReasonFlags.unspecified,
    next_update_days: int = 30,
) -> x509.CertificateRevocationList:
    """
    Thêm cert_to_revoke vào CRL và cập nhật file crl.pem.

    Tham số:
        cert_to_revoke   : Chứng chỉ cần thu hồi
        ca_key           : Private key của CA
        ca_cert          : Certificate của CA
        reason           : Lý do thu hồi (x509.ReasonFlags)
        next_update_days : Số ngày trước khi CRL hết hạn

    Trả về CRL mới.
    """
    # Nạp CRL hiện có (nếu có), ngược lại tạo mới
    existing_crl = _load_crl()

    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=next_update_days))
    )

    # Giữ lại các entry đã thu hồi trước đó
    if existing_crl is not None:
        for revoked in existing_crl:
            builder = builder.add_revoked_certificate(revoked)

    # Thêm chứng chỉ mới thu hồi
    revoked_cert = (
        x509.RevokedCertificateBuilder()
        .serial_number(cert_to_revoke.serial_number)
        .revocation_date(now)
        .add_extension(x509.CRLReason(reason), critical=False)
        .build(default_backend())
    )
    builder = builder.add_revoked_certificate(revoked_cert)

    new_crl = builder.sign(ca_key, hashes.SHA256(), default_backend())
    _save_crl(new_crl)

    print(
        f"[revoke_certificate] Đã thu hồi serial={cert_to_revoke.serial_number} "
        f"(lý do: {reason.name}) -> {CRL_PATH}"
    )
    return new_crl


# ---------------------------------------------------------------------------
# Kiểm tra trạng thái thu hồi
# ---------------------------------------------------------------------------

def check_revocation_status(cert: x509.Certificate) -> dict:
    """
    Kiểm tra xem cert có nằm trong CRL hay không.

    Trả về dict:
        {
            "serial"  : <số serial (hex)>,
            "revoked" : True / False,
            "reason"  : <tên lý do nếu bị thu hồi, else None>,
            "date"    : <ngày thu hồi nếu bị thu hồi, else None>,
        }
    """
    crl = _load_crl()
    serial_hex = hex(cert.serial_number)

    result = {
        "serial" : serial_hex,
        "revoked": False,
        "reason" : None,
        "date"   : None,
    }

    if crl is None:
        print("[check_revocation_status] Không tìm thấy file CRL. Giả sử chứng chỉ CHƯA bị thu hồi.")
        return result

    for revoked in crl:
        if revoked.serial_number == cert.serial_number:
            result["revoked"] = True
            result["date"]    = revoked.revocation_date_utc

            # Lấy lý do thu hồi nếu có
            try:
                ext = revoked.extensions.get_extension_for_class(x509.CRLReason)
                result["reason"] = ext.value.reason.name
            except x509.ExtensionNotFound:
                result["reason"] = "unspecified"

            print(
                f"[check_revocation_status] Serial {serial_hex} -> BỊ THU HỒI "
                f"(lý do: {result['reason']}, ngày: {result['date']})"
            )
            return result

    print(f"[check_revocation_status] Serial {serial_hex} -> CHƯA bị thu hồi ✓")
    return result


# ---------------------------------------------------------------------------
# Hàm nội bộ: lưu / nạp CRL
# ---------------------------------------------------------------------------

def _save_crl(crl: x509.CertificateRevocationList):
    with open(CRL_PATH, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))


def _load_crl():
    if not os.path.exists(CRL_PATH):
        return None
    with open(CRL_PATH, "rb") as f:
        return x509.load_pem_x509_crl(f.read(), default_backend())
