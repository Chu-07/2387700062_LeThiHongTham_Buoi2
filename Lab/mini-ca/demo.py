"""
demo.py
-------
Kich ban chay thu he thong mini-CA qua CLI.
Thong tin ca nhan: Le_Thi_Hong_Tham / 2387700062_HUTECH
"""

import sys

# Ho tro Unicode tren Windows CMD / PowerShell
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
from ca_utils import (
    create_root_ca,
    create_intermediate_ca,
    issue_certificate,
    verify_certificate_chain,
    load_key,
    load_cert,
)
from revoke_utils import create_empty_crl, revoke_certificate, check_revocation_status


# ---------------------------------------------------------------------------
# Thông tin cá nhân
# ---------------------------------------------------------------------------
STUDENT_NAME = "Le_Thi_Hong_Tham"
STUDENT_ID   = "2387700062_HUTECH"
COUNTRY      = "VN"


def banner(text: str):
    width = 60
    print("\n" + "=" * width)
    print(f"  {text}")
    print("=" * width)


# ---------------------------------------------------------------------------
# Bước 1 – Tạo Root CA
# ---------------------------------------------------------------------------
def step_create_root_ca():
    banner("BƯỚC 1: Tạo Root CA")
    root_subject = {
        "common_name": f"Root-CA-{STUDENT_NAME}",
        "org"        : STUDENT_ID,
        "country"    : COUNTRY,
    }
    root_key, root_cert = create_root_ca(root_subject, valid_days=3650)
    print(f"  Subject : {root_cert.subject.rfc4514_string()}")
    print(f"  Serial  : {hex(root_cert.serial_number)}")
    print(f"  Hạn dùng: {root_cert.not_valid_after_utc}")
    return root_key, root_cert


# ---------------------------------------------------------------------------
# Bước 2 – Tạo Intermediate CA
# ---------------------------------------------------------------------------
def step_create_intermediate_ca(root_key, root_cert):
    banner("BƯỚC 2: Tạo Intermediate CA")
    inter_subject = {
        "common_name": f"Intermediate-CA-{STUDENT_NAME}",
        "org"        : STUDENT_ID,
        "country"    : COUNTRY,
    }
    inter_key, inter_cert = create_intermediate_ca(inter_subject, root_key, root_cert, valid_days=1825)
    print(f"  Subject : {inter_cert.subject.rfc4514_string()}")
    print(f"  Issuer  : {inter_cert.issuer.rfc4514_string()}")
    print(f"  Serial  : {hex(inter_cert.serial_number)}")
    return inter_key, inter_cert


# ---------------------------------------------------------------------------
# Bước 3 – Phát hành chứng chỉ end-entity
# ---------------------------------------------------------------------------
def step_issue_certificate(inter_key, inter_cert):
    banner("BƯỚC 3: Phát hành chứng chỉ end-entity")
    entity_subject = {
        "common_name": STUDENT_NAME,
        "org"        : STUDENT_ID,
        "country"    : COUNTRY,
    }
    san_dns = [f"{STUDENT_NAME.lower()}.hutech.edu.vn", "localhost"]
    entity_key, entity_cert = issue_certificate(
        entity_subject, inter_key, inter_cert,
        valid_days=365, san_dns=san_dns
    )
    print(f"  Subject : {entity_cert.subject.rfc4514_string()}")
    print(f"  SAN DNS : {san_dns}")
    print(f"  Serial  : {hex(entity_cert.serial_number)}")
    return entity_key, entity_cert


# ---------------------------------------------------------------------------
# Bước 4 – Xác minh chuỗi chứng chỉ
# ---------------------------------------------------------------------------
def step_verify_chain(entity_cert, inter_cert, root_cert):
    banner("BƯỚC 4: Xác minh chuỗi chứng chỉ")
    ok = verify_certificate_chain(entity_cert, inter_cert, root_cert)
    if ok:
        print("  >> Kết quả: CHUỖI HỢP LỆ ✓")
    else:
        print("  >> Kết quả: CHUỖI KHÔNG HỢP LỆ ✗")
    return ok


# ---------------------------------------------------------------------------
# Bước 5 – Tạo CRL và thu hồi chứng chỉ
# ---------------------------------------------------------------------------
def step_revoke(inter_key, inter_cert, entity_cert):
    from cryptography import x509 as _x509

    banner("BƯỚC 5: Quản lý thu hồi chứng chỉ (CRL)")

    # Tạo CRL rỗng
    print("[5a] Tạo CRL rỗng...")
    create_empty_crl(inter_key, inter_cert)

    # Kiểm tra trước khi thu hồi
    print("\n[5b] Kiểm tra trạng thái TRƯỚC khi thu hồi:")
    status_before = check_revocation_status(entity_cert)
    print(f"     Bị thu hồi: {status_before['revoked']}")

    # Thu hồi chứng chỉ
    print("\n[5c] Thu hồi chứng chỉ...")
    revoke_certificate(
        entity_cert, inter_key, inter_cert,
        reason=_x509.ReasonFlags.key_compromise
    )

    # Kiểm tra sau khi thu hồi
    print("\n[5d] Kiểm tra trạng thái SAU khi thu hồi:")
    status_after = check_revocation_status(entity_cert)
    print(f"     Bị thu hồi : {status_after['revoked']}")
    print(f"     Lý do      : {status_after['reason']}")
    print(f"     Ngày       : {status_after['date']}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    banner(f"DEMO mini-CA – {STUDENT_NAME} ({STUDENT_ID})")
    print("Bắt đầu kịch bản thử nghiệm CA...\n")

    try:
        root_key,   root_cert   = step_create_root_ca()
        inter_key,  inter_cert  = step_create_intermediate_ca(root_key, root_cert)
        entity_key, entity_cert = step_issue_certificate(inter_key, inter_cert)
        step_verify_chain(entity_cert, inter_cert, root_cert)
        step_revoke(inter_key, inter_cert, entity_cert)

        banner("HOÀN THÀNH – Tất cả các bước thành công!")
        print(f"  Các file được lưu trong thư mục: certs/")

    except Exception as exc:
        print(f"\n[LỖI] {exc}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
