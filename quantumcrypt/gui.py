# quantumcrypt/gui.py
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QTextEdit, QLineEdit, QLabel
from quantumcrypt.core import kyber, sphincs, mceliece
from quantumcrypt.hybrid import pq_aes_wrapper
from quantumcrypt.utils import key_utils
import sys
import base64
import os

class QuantumCryptGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QuantumCrypt")
        self.setGeometry(100, 100, 600, 400)
        layout = QVBoxLayout()
        self.generate_btn = QPushButton("Generate Kyber Keypair")
        self.generate_btn.clicked.connect(self.generate_kyber)
        layout.addWidget(self.generate_btn)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password for secret key (optional)")
        layout.addWidget(self.password_input)
        self.output = QTextEdit("Output will appear here")
        self.output.setReadOnly(True)
        layout.addWidget(self.output)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def generate_kyber(self):
        password = self.password_input.text() or None
        pub, priv = kyber.generate_keypair()
        pub_path, priv_path = "pub.key", "priv.key"
        os.makedirs("keys", exist_ok=True)
        if password:
            pub_path = f"keys/pub_{password}.key"
            priv_path = f"keys/priv_{password}.key"
        else:
            pub_path = "keys/pub.key"
            priv_path = "keys/priv.key"
        key_utils.save_key(pub, pub_path)
        key_utils.save_key(priv, priv_path, password=password)
        self.output.setText(f"Public Key saved to {pub_path}\nSecret Key saved to {priv_path}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = QuantumCryptGUI()
    window.show()
    sys.exit(app.exec_())