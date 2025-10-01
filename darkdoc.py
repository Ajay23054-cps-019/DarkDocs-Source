#!/usr/bin/env python3
"""
DarkDoc P2P - Encrypted File Transfer (fixed & improved)
- Proper PIN approval flow using a modal popup from the main thread
- Robust local IP detection (doesn't return 127.0.1.1)
- Clean QR display and scanner flow
- Safer socket handling and clearer UI updates

Run: python3 darkdoc_p2p.py
"""

import socket
import os
import threading
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
import qrcode
from PIL import Image, ImageTk
import cv2
from pyzbar.pyzbar import decode
import random
import io
import tempfile
import time

PORT = 5001
CHUNK_SIZE = 64 * 1024  # smaller chunk is friendlier for many networks
KEY_LEN = 32

# ---------- crypto helpers ----------
def derive_shared_key(local_private: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared = local_private.exchange(peer_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=b"darkdoc file transfer")
    return hkdf.derive(shared)


def encrypt_chunk(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_chunk(enc: bytes, key: bytes) -> bytes:
    nonce = enc[:12]
    ct = enc[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# ---------- networking helpers ----------

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf


def send_prefixed(sock: socket.socket, data: bytes):
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_prefixed(sock: socket.socket) -> bytes:
    length = int.from_bytes(recv_exact(sock, 4), "big")
    return recv_exact(sock, length)

# ---------- helper to get local LAN IP (better than gethostbyname) ----------

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # doesn't actually connect, just used to determine the outbound interface
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            return ip
    except Exception:
        # fallback
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

# ---------- QR helpers ----------

def generate_qr_image(ip, port):
    url = f"darkdoc://{ip}:{port}"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    qr_img = qr.make_image(fill_color="black", back_color="white")

    # Convert to bytes
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    buf.seek(0)
    return buf, url


def scan_qr_code():
    cap = cv2.VideoCapture(0)
    server_ip, server_port = None, None
    if not cap.isOpened():
        return None, None
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        for code in decode(frame):
            data = code.data.decode("utf-8")
            if data.startswith("darkdoc://"):
                parts = data.replace("darkdoc://", "").split(":")
                server_ip = parts[0]
                try:
                    server_port = int(parts[1])
                except Exception:
                    server_port = PORT
                cap.release()
                cv2.destroyAllWindows()
                return server_ip, server_port
        cv2.imshow("Scan QR - Press Q to cancel", frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break
    cap.release()
    cv2.destroyAllWindows()
    return None, None

# ---------- send / receive logic ----------

def threaded_send_file(filename, update_ui_callback=None, progress_callback=None, pin_callback=None):
    """Server/sender side. pin_callback is called as pin_callback(received_pin) and MUST return True/False.
    The UI must ensure the callback runs on the main thread; here we only call it and wait for its result.
    """
    try:
        if not os.path.exists(filename):
            raise FileNotFoundError("File does not exist")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", PORT))
            s.listen(1)
            local_ip = get_local_ip()
            if update_ui_callback:
                update_ui_callback(f"Server on {local_ip}:{PORT}, waiting for connection...")

            conn, addr = s.accept()
            with conn:
                if update_ui_callback:
                    update_ui_callback(f"Connected by {addr}")

                # key exchange
                local_priv = X25519PrivateKey.generate()
                local_pub = local_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                send_prefixed(conn, local_pub)
                peer_pub_bytes = recv_prefixed(conn)
                key = derive_shared_key(local_priv, peer_pub_bytes)

                # PIN verification: receiver sends PIN, sender must show and approve
                recv_pin = recv_prefixed(conn).decode()
                if pin_callback:
                    try:
                        pin_approved = pin_callback(recv_pin)
                    except Exception as e:
                        pin_approved = False
                    if not pin_approved:
                        send_prefixed(conn, b"PIN_MISMATCH")
                        if update_ui_callback:
                            update_ui_callback("❌ PIN mismatch! Transfer aborted.")
                        return
                    else:
                        send_prefixed(conn, b"PIN_OK")

                # send encrypted metadata
                filesize = os.path.getsize(filename)
                meta = json.dumps({"name": os.path.basename(filename), "size": filesize}).encode()
                send_prefixed(conn, encrypt_chunk(meta, key))

                # send file with progress
                sent = 0
                with open(filename, "rb") as f:
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        send_prefixed(conn, encrypt_chunk(chunk, key))
                        sent += len(chunk)
                        if update_ui_callback:
                            update_ui_callback(f"Sent {sent}/{filesize} bytes")
                        if progress_callback:
                            progress_callback(sent, filesize)
                if update_ui_callback:
                    update_ui_callback(f"✅ File '{os.path.basename(filename)}' sent successfully.")
    except Exception as e:
        if update_ui_callback:
            update_ui_callback(f"Error: {e}")


def threaded_receive_file(server_ip, update_ui_callback=None, progress_callback=None, save_path=None):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(20)
            s.connect((server_ip, PORT))
            if update_ui_callback:
                update_ui_callback(f"Connected to {server_ip}:{PORT}")

            # key exchange
            server_pub = recv_prefixed(s)
            local_priv = X25519PrivateKey.generate()
            local_pub = local_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            send_prefixed(s, local_pub)
            key = derive_shared_key(local_priv, server_pub)

            # PIN generation & send to sender
            transfer_pin = str(random.randint(1000, 9999))
            if update_ui_callback:
                update_ui_callback(f"Your PIN for this transfer: {transfer_pin}")
            send_prefixed(s, transfer_pin.encode())

            # wait for sender approval
            resp = recv_prefixed(s)
            if resp != b"PIN_OK":
                if update_ui_callback:
                    update_ui_callback("Sender did not approve PIN! Transfer aborted.")
                return

            # metadata
            enc_meta = recv_prefixed(s)
            meta = json.loads(decrypt_chunk(enc_meta, key).decode())
            filename = meta.get("name", "received_file")
            filesize = int(meta.get("size", 0))
            if update_ui_callback:
                update_ui_callback(f"Receiving {filename} ({filesize} bytes)")

            if not save_path:
                save_path = os.path.join(os.getcwd(), "received_" + filename)

            received = 0
            with open(save_path, "wb") as f:
                while received < filesize:
                    enc_chunk = recv_prefixed(s)
                    chunk = decrypt_chunk(enc_chunk, key)
                    f.write(chunk)
                    received += len(chunk)
                    if update_ui_callback:
                        update_ui_callback(f"Received {received}/{filesize} bytes")
                    if progress_callback:
                        progress_callback(received, filesize)
            if update_ui_callback:
                update_ui_callback(f"✅ File saved to {save_path}")
    except Exception as e:
        if update_ui_callback:
            update_ui_callback(f"Error: {e}")

# ---------- UI popups ----------
class PinVerificationPopup:
    def __init__(self, parent, pin, callback):
        self.callback = callback
        self.top = tk.Toplevel(parent)
        self.top.title("PIN Verification")
        self.top.geometry("400x200")
        self.top.resizable(False, False)
        self.top.transient(parent)
        self.top.grab_set()

        # Center the window
        self.top.geometry(f"+{parent.winfo_rootx()+50}+{parent.winfo_rooty()+50}")

        main_frame = ttk.Frame(self.top, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text=f"Receiver generated PIN: {pin}", font=("Arial", 12, "bold")).pack(pady=(0, 10))
        ttk.Label(main_frame, text="Enter PIN to approve transfer:", font=("Arial", 10)).pack(pady=(0, 10))

        self.pin_input = ttk.Entry(main_frame, font=("Arial", 14), justify=tk.CENTER, show="•")
        self.pin_input.pack(pady=(0, 20), fill=tk.X)
        self.pin_input.focus()

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)

        ttk.Button(button_frame, text="Approve", command=self.approve_transfer).pack(side=tk.LEFT, expand=True, padx=(0, 5))
        ttk.Button(button_frame, text="Cancel", command=self.cancel_transfer).pack(side=tk.RIGHT, expand=True, padx=(5, 0))

        self.top.bind('<Return>', lambda e: self.approve_transfer())
        self.top.bind('<Escape>', lambda e: self.cancel_transfer())

    def approve_transfer(self):
        entered_pin = self.pin_input.get().strip()
        self.callback(entered_pin)
        self.top.destroy()

    def cancel_transfer(self):
        self.callback(None)
        self.top.destroy()

class QRDisplayPopup:
    def __init__(self, parent, ip, port):
        self.top = tk.Toplevel(parent)
        self.top.title("Scan this QR on Receiver")
        self.top.geometry("400x500")
        self.top.resizable(False, False)
        self.top.transient(parent)
        self.top.grab_set()

        # Center the window
        self.top.geometry(f"+{parent.winfo_rootx()+50}+{parent.winfo_rooty()+50}")

        main_frame = ttk.Frame(self.top, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        try:
            # Generate QR code
            qr_buf, url = generate_qr_image(ip, port)

            # Create PIL Image and convert to PhotoImage
            qr_image = Image.open(qr_buf)

            # Resize for better display
            qr_image = qr_image.resize((300, 300), Image.Resampling.LANCZOS)
            self.photo = ImageTk.PhotoImage(qr_image)

            qr_label = ttk.Label(main_frame, image=self.photo)
            qr_label.pack(pady=(0, 15))

            url_label = ttk.Label(main_frame, text=url, font=("Arial", 9), wraplength=350)
            url_label.pack(pady=(0, 15))

            ttk.Label(main_frame, text="Share this QR code with the receiver", font=("Arial", 10, "bold")).pack(pady=(0, 10))

            ttk.Button(main_frame, text="Close", command=self.top.destroy).pack()

            # Store reference to prevent garbage collection
            self.qr_image = qr_image

        except Exception as e:
            ttk.Label(main_frame, text=f"Error generating QR code: {e}", foreground="red").pack()
            ttk.Button(main_frame, text="Close", command=self.top.destroy).pack()

# ---------- Main app ----------
class DarkDocApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DarkDoc P2P - Encrypted File Transfer")
        self.root.geometry("500x440")
        self.root.resizable(False, False)

        # Configure style
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Arial", 10), padding=6)
        self.style.configure("Title.TLabel", font=("Arial", 16, "bold"))
        self.style.configure("Status.TLabel", font=("Arial", 10))
        self.style.configure("Hint.TLabel", font=("Arial", 9))

        self.setup_ui()

    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="DarkDoc P2P — Encrypted (LAN)", style="Title.TLabel")
        title_label.pack(pady=(0, 12))

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100, length=460)
        self.progress_bar.pack(pady=(0, 12), fill=tk.X)

        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(0, 12), fill=tk.X)

        # Send button
        send_btn = ttk.Button(button_frame, text="📤 Send File", command=self.start_send)
        send_btn.pack(pady=5, fill=tk.X)

        # Receive button
        receive_btn = ttk.Button(button_frame, text="📥 Receive File", command=self.start_receive)
        receive_btn.pack(pady=5, fill=tk.X)

        # Scan QR button
        scan_btn = ttk.Button(button_frame, text="📷 Scan QR Code", command=self.scan_qr)
        scan_btn.pack(pady=5, fill=tk.X)

        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.pack(fill=tk.BOTH, expand=True)

        self.status_text = tk.Text(status_frame, height=10, width=50, font=("Arial", 9), wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(status_frame, orient=tk.VERTICAL, command=self.status_text.yview)
        self.status_text.configure(yscrollcommand=scrollbar.set)

        self.status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Hint
        hint_label = ttk.Label(main_frame,
                              text="Both devices must be on the same LAN. Allow firewall if needed.",
                              style="Hint.TLabel")
        hint_label.pack(pady=(10, 0))

        # Initialize status
        self.update_status("Ready - Select an option to begin")

    def update_status(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        # don't call update() excessively; only update the GUI event loop
        self.root.update_idletasks()

    def update_progress(self, current, total):
        if total > 0:
            percentage = (current / total) * 100
            self.progress_var.set(percentage)
            self.root.update_idletasks()

    def start_send(self):
        filename = filedialog.askopenfilename(title="Select file to send")
        if filename:
            try:
                local_ip = get_local_ip()
                self.update_status(f"Selected file: {os.path.basename(filename)}")
                self.update_status(f"Your IP: {local_ip}")

                # Show QR code popup
                QRDisplayPopup(self.root, local_ip, PORT)

                # Define pin_callback that will run in the network thread but schedule UI on main thread
                def pin_verification_callback(received_pin: str) -> bool:
                    result_event = threading.Event()
                    result_container = {"approved": False}

                    def on_response(entered_pin):
                        try:
                            if entered_pin is None:
                                result_container["approved"] = False
                            else:
                                result_container["approved"] = (entered_pin.strip() == received_pin)
                        finally:
                            result_event.set()

                    # schedule popup on main thread
                    self.root.after(0, lambda: PinVerificationPopup(self.root, received_pin, on_response))

                    # wait for user to respond (timeout optional)
                    waited = result_event.wait(timeout=300)  # 5 minutes max
                    if not waited:
                        return False
                    return result_container["approved"]

                t = threading.Thread(
                    target=threaded_send_file,
                    args=(filename, self.update_status, self.update_progress, pin_verification_callback),
                    daemon=True
                )
                t.start()

            except Exception as e:
                self.update_status(f"Error: {e}")

    def start_receive(self):
        ip = simpledialog.askstring("Server IP", "Enter server IP address:", parent=self.root)
        if ip:
            # optional: let user choose save path
            save_dir = filedialog.askdirectory(title="Select folder to save received file")
            save_path = None
            if save_dir:
                save_path = save_dir

            t = threading.Thread(
                target=threaded_receive_file,
                args=(ip, self.update_status, self.update_progress),
                daemon=True
            )
            t.start()

    def scan_qr(self):
        def scan_thread():
            self.update_status("Starting QR scanner...")
            ip, port = scan_qr_code()
            if ip:
                self.update_status(f"Scanned IP: {ip}:{port}")
                t = threading.Thread(
                    target=threaded_receive_file,
                    args=(ip, self.update_status, self.update_progress),
                    daemon=True
                )
                t.start()
            else:
                self.update_status("No QR code detected or scan cancelled.")

        threading.Thread(target=scan_thread, daemon=True).start()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = DarkDocApp()
    app.run()
