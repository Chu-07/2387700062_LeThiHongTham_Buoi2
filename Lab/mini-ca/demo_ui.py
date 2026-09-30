"""
demo_ui.py
----------
Giao diện người dùng tkinter cho hệ thống mini-CA.
Thông tin cá nhân: Le_Thi_Hong_Tham / 2387700062_HUTECH

5 chức năng:
  1. Tạo CA          – Tạo Root CA và Intermediate CA
  2. Phát hành Cert  – Phát hành chứng chỉ end-entity
  3. Kiểm tra chuỗi  – Xác minh chuỗi tin cậy
  4. Thu hồi Cert    – Thêm chứng chỉ vào CRL
  5. Kiểm tra OCSP   – Kiểm tra trạng thái thu hồi (mô phỏng OCSP)
"""

import io
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ── Redirect stdout để hiển thị trong Text widget ──────────────────────────
class _TextRedirector(io.TextIOBase):
    def __init__(self, widget: scrolledtext.ScrolledText):
        self._widget = widget

    def write(self, text: str):
        self._widget.configure(state="normal")
        self._widget.insert(tk.END, text)
        self._widget.see(tk.END)
        self._widget.configure(state="disabled")
        return len(text)

    def flush(self):
        pass


# ── Thông tin cá nhân ──────────────────────────────────────────────────────
STUDENT_NAME = "Le_Thi_Hong_Tham"
STUDENT_ID   = "2387700062_HUTECH"
COUNTRY      = "VN"

# Trạng thái toàn cục (giữ các đối tượng key/cert trong RAM)
_state = {
    "root_key"  : None,
    "root_cert" : None,
    "inter_key" : None,
    "inter_cert": None,
    "entity_key": None,
    "entity_cert": None,
}


# ── Hàm xử lý cho từng nút ────────────────────────────────────────────────

def _run_in_thread(fn):
    """Chạy fn() trong thread riêng để không đóng băng GUI."""
    t = threading.Thread(target=fn, daemon=True)
    t.start()


def action_create_ca():
    """Nút 1: Tạo Root CA + Intermediate CA."""
    from ca_utils import create_root_ca, create_intermediate_ca

    def _work():
        print("\n" + "=" * 55)
        print("  [1] TẠO ROOT CA & INTERMEDIATE CA")
        print("=" * 55)
        try:
            root_subject = {
                "common_name": f"Root-CA-{STUDENT_NAME}",
                "org"        : STUDENT_ID,
                "country"    : COUNTRY,
            }
            rk, rc = create_root_ca(root_subject, valid_days=3650)
            _state["root_key"]  = rk
            _state["root_cert"] = rc

            inter_subject = {
                "common_name": f"Intermediate-CA-{STUDENT_NAME}",
                "org"        : STUDENT_ID,
                "country"    : COUNTRY,
            }
            ik, ic = create_intermediate_ca(inter_subject, rk, rc, valid_days=1825)
            _state["inter_key"]  = ik
            _state["inter_cert"] = ic

            print(f"\n  Root CA serial   : {hex(rc.serial_number)}")
            print(f"  Inter CA serial  : {hex(ic.serial_number)}")
            print("\n  >> Tạo CA THÀNH CÔNG ✓")
        except Exception as e:
            print(f"\n  [LỖI] {e}")

    _run_in_thread(_work)


def action_issue_cert():
    """Nút 2: Phát hành chứng chỉ end-entity."""
    from ca_utils import issue_certificate

    def _work():
        print("\n" + "=" * 55)
        print("  [2] PHÁT HÀNH CHỨNG CHỈ END-ENTITY")
        print("=" * 55)
        if _state["inter_key"] is None or _state["inter_cert"] is None:
            print("  [!] Chưa tạo CA. Hãy nhấn 'Tạo CA' trước.")
            return
        try:
            entity_subject = {
                "common_name": STUDENT_NAME,
                "org"        : STUDENT_ID,
                "country"    : COUNTRY,
            }
            san_dns = [f"{STUDENT_NAME.lower()}.hutech.edu.vn", "localhost"]
            ek, ec = issue_certificate(
                entity_subject,
                _state["inter_key"],
                _state["inter_cert"],
                valid_days=365,
                san_dns=san_dns,
            )
            _state["entity_key"]  = ek
            _state["entity_cert"] = ec
            print(f"\n  Subject : {ec.subject.rfc4514_string()}")
            print(f"  SAN DNS : {san_dns}")
            print(f"  Serial  : {hex(ec.serial_number)}")
            print(f"  Hạn dùng: {ec.not_valid_after_utc}")
            print("\n  >> Phát hành chứng chỉ THÀNH CÔNG ✓")
        except Exception as e:
            print(f"\n  [LỖI] {e}")

    _run_in_thread(_work)


def action_verify_chain():
    """Nút 3: Kiểm tra chuỗi chứng chỉ."""
    from ca_utils import verify_certificate_chain

    def _work():
        print("\n" + "=" * 55)
        print("  [3] KIỂM TRA CHUỖI CHỨNG CHỈ")
        print("=" * 55)
        if any(v is None for v in [
            _state["entity_cert"], _state["inter_cert"], _state["root_cert"]
        ]):
            print("  [!] Chưa đủ dữ liệu. Hãy thực hiện Tạo CA và Phát hành Cert trước.")
            return
        try:
            ok = verify_certificate_chain(
                _state["entity_cert"],
                _state["inter_cert"],
                _state["root_cert"],
            )
            if ok:
                print("\n  >> Chuỗi chứng chỉ HỢP LỆ ✓")
            else:
                print("\n  >> Chuỗi chứng chỉ KHÔNG HỢP LỆ ✗")
        except Exception as e:
            print(f"\n  [LỖI] {e}")

    _run_in_thread(_work)


def action_revoke_cert():
    """Nút 4: Thu hồi chứng chỉ (thêm vào CRL)."""
    from cryptography import x509 as _x509
    from revoke_utils import create_empty_crl, revoke_certificate

    def _work():
        print("\n" + "=" * 55)
        print("  [4] THU HỒI CHỨNG CHỈ (CRL)")
        print("=" * 55)
        if _state["entity_cert"] is None:
            print("  [!] Chưa phát hành chứng chỉ nào để thu hồi.")
            return
        if _state["inter_key"] is None or _state["inter_cert"] is None:
            print("  [!] Chưa có Intermediate CA.")
            return
        try:
            # Tạo / cập nhật CRL
            revoke_certificate(
                _state["entity_cert"],
                _state["inter_key"],
                _state["inter_cert"],
                reason=_x509.ReasonFlags.key_compromise,
            )
            print(f"\n  Serial bị thu hồi: {hex(_state['entity_cert'].serial_number)}")
            print("  Lý do            : key_compromise")
            print("\n  >> Thu hồi chứng chỉ THÀNH CÔNG ✓")
        except Exception as e:
            print(f"\n  [LỖI] {e}")

    _run_in_thread(_work)


def action_check_ocsp():
    """Nút 5: Kiểm tra trạng thái OCSP (mô phỏng từ CRL)."""
    from revoke_utils import check_revocation_status

    def _work():
        print("\n" + "=" * 55)
        print("  [5] KIỂM TRA TRẠNG THÁI OCSP (mô phỏng)")
        print("=" * 55)
        if _state["entity_cert"] is None:
            print("  [!] Chưa có chứng chỉ nào để kiểm tra.")
            return
        try:
            result = check_revocation_status(_state["entity_cert"])
            print(f"\n  Serial  : {result['serial']}")
            print(f"  Thu hồi : {'CÓ ✗' if result['revoked'] else 'KHÔNG ✓'}")
            if result["revoked"]:
                print(f"  Lý do   : {result['reason']}")
                print(f"  Ngày    : {result['date']}")
            else:
                print("  >> Chứng chỉ HỢP LỆ, chưa bị thu hồi ✓")
        except Exception as e:
            print(f"\n  [LỖI] {e}")

    _run_in_thread(_work)


# ── Xây dựng giao diện chính ───────────────────────────────────────────────

def build_ui():
    root = tk.Tk()
    root.title(f"mini-CA Demo – {STUDENT_NAME} ({STUDENT_ID})")
    root.geometry("820x640")
    root.resizable(True, True)
    root.configure(bg="#1e1e2e")

    # ── Màu sắc & font ──────────────────────────────────────────
    BG       = "#1e1e2e"
    PANEL_BG = "#2a2a3e"
    ACCENT   = "#89b4fa"    # xanh dương pastel
    FG       = "#cdd6f4"
    BTN_FG   = "#1e1e2e"
    FONT_HDR = ("Segoe UI", 13, "bold")
    FONT_BTN = ("Segoe UI", 11, "bold")
    FONT_LOG = ("Consolas", 10)

    # ── Tiêu đề ─────────────────────────────────────────────────
    hdr = tk.Frame(root, bg=ACCENT, pady=10)
    hdr.pack(fill="x")
    tk.Label(
        hdr,
        text=f"🔐  mini Certificate Authority",
        font=("Segoe UI", 16, "bold"),
        bg=ACCENT, fg=BTN_FG,
    ).pack()
    tk.Label(
        hdr,
        text=f"{STUDENT_NAME}  ·  {STUDENT_ID}",
        font=("Segoe UI", 10),
        bg=ACCENT, fg="#1e1e2e",
    ).pack()

    # ── Khung nút chức năng ──────────────────────────────────────
    btn_frame = tk.Frame(root, bg=BG, pady=12)
    btn_frame.pack(fill="x", padx=20)

    buttons = [
        ("1. Tạo CA",          "🏗",  action_create_ca,   "#a6e3a1"),  # xanh lá
        ("2. Phát hành Cert",  "📜",  action_issue_cert,  "#89b4fa"),  # xanh dương
        ("3. Kiểm tra chuỗi", "🔗",  action_verify_chain,"#f9e2af"),  # vàng
        ("4. Thu hồi Cert",   "🚫",  action_revoke_cert, "#f38ba8"),  # đỏ
        ("5. Kiểm tra OCSP",  "🔍",  action_check_ocsp,  "#cba6f7"),  # tím
    ]

    for label, icon, cmd, color in buttons:
        b = tk.Button(
            btn_frame,
            text=f"{icon}  {label}",
            font=FONT_BTN,
            bg=color,
            fg=BTN_FG,
            activebackground=color,
            activeforeground=BTN_FG,
            relief="flat",
            cursor="hand2",
            padx=14,
            pady=8,
            command=cmd,
        )
        b.pack(side="left", padx=6)

    # ── Separator ────────────────────────────────────────────────
    sep = ttk.Separator(root, orient="horizontal")
    sep.pack(fill="x", padx=20, pady=4)

    # ── Log output ───────────────────────────────────────────────
    log_frame = tk.Frame(root, bg=PANEL_BG, bd=0)
    log_frame.pack(fill="both", expand=True, padx=20, pady=(0, 12))

    tk.Label(
        log_frame,
        text="  📋  Nhật ký hoạt động",
        font=FONT_HDR,
        bg=PANEL_BG,
        fg=ACCENT,
        anchor="w",
        pady=6,
    ).pack(fill="x")

    log_box = scrolledtext.ScrolledText(
        log_frame,
        font=FONT_LOG,
        bg="#11111b",
        fg=FG,
        insertbackground=FG,
        state="disabled",
        wrap="word",
        bd=0,
        relief="flat",
    )
    log_box.pack(fill="both", expand=True, padx=6, pady=(0, 8))

    # ── Nút Xoá log ──────────────────────────────────────────────
    def clear_log():
        log_box.configure(state="normal")
        log_box.delete("1.0", tk.END)
        log_box.configure(state="disabled")

    btn_clear = tk.Button(
        root,
        text="🗑  Xoá nhật ký",
        font=("Segoe UI", 9),
        bg="#45475a",
        fg=FG,
        activebackground="#585b70",
        activeforeground=FG,
        relief="flat",
        cursor="hand2",
        padx=10,
        pady=4,
        command=clear_log,
    )
    btn_clear.pack(anchor="e", padx=22, pady=(0, 10))

    # ── Redirect stdout -> log_box ───────────────────────────────
    redirector = _TextRedirector(log_box)
    sys.stdout = redirector

    # ── Thông điệp chào mừng ─────────────────────────────────────
    print(f"Chào mừng đến với mini-CA Demo!")
    print(f"Sinh viên : {STUDENT_NAME}")
    print(f"MSSV/Org  : {STUDENT_ID}")
    print("─" * 50)
    print("Nhấn các nút bên trên để thực hiện từng chức năng.")
    print("Kết quả sẽ hiển thị tại đây.\n")

    root.mainloop()
    sys.stdout = sys.__stdout__


if __name__ == "__main__":
    build_ui()
