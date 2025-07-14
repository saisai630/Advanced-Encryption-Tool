# Importing Required Libraries
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

from PyQt5.QtWidgets import (
    QApplication, QVBoxLayout, QPushButton, QLabel, QFileDialog, 
    QLineEdit, QHBoxLayout, QWidget, QGroupBox, QMessageBox
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
import sys

# Core Logic: Encryption and Decryption
def generate_key(password: str, salt: bytes) -> bytes:
    """Generate a key using PBKDF2 with a given password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file: str, password: str):
    """Encrypt a file using AES-256."""
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    encrypted_data = base64.b64encode(salt + iv + ciphertext)

    with open(input_file + '.enc', 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(encrypted_file: str, password: str):
    """Decrypt a file that was encrypted using AES-256."""
    with open(encrypted_file, 'rb') as f:
        encrypted_data = base64.b64decode(f.read())

    salt, iv, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    output_file = encrypted_file.replace('.enc', '_decrypted')
    with open(output_file, 'wb') as f:
        f.write(plaintext)

# GUI Code
class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.file_name = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Advanced Encryption Tool")
        self.setGeometry(200, 100, 800, 500)  # Increased window size

        # Main Layout
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Title Label
        title_label = QLabel("🔒 Advanced Encryption Tool")
        title_label.setStyleSheet("font-size: 32px; font-weight: bold; color: #333;")  # Larger font size
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)

        # File Selection Group
        file_group = QGroupBox("Step 1: Select a File")
        file_layout = QVBoxLayout()

        self.label = QLabel("No file selected")
        self.label.setStyleSheet("font-size: 18px; color: #666;")  # Larger font size
        file_layout.addWidget(self.label)

        file_button = QPushButton("Browse File")
        file_button.setIcon(QIcon.fromTheme("document-open"))
        file_button.setStyleSheet("font-size: 18px; padding: 12px;")  # Larger font size and padding
        file_button.clicked.connect(self.open_file)
        file_layout.addWidget(file_button)

        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        # Password Input Group
        password_group = QGroupBox("Step 2: Enter Password")
        password_layout = QVBoxLayout()

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter a secure password")
        self.password_input.setStyleSheet("font-size: 18px; padding: 12px;")  # Larger font size and padding
        password_layout.addWidget(self.password_input)

        password_group.setLayout(password_layout)
        main_layout.addWidget(password_group)

        # Action Buttons
        button_layout = QHBoxLayout()

        encrypt_button = QPushButton("Encrypt File")
        encrypt_button.setIcon(QIcon.fromTheme("lock"))
        encrypt_button.setStyleSheet(
            "font-size: 18px; padding: 15px; background-color: #4CAF50; color: white;"  # Larger font size and padding
        )
        encrypt_button.clicked.connect(self.encrypt_file)
        button_layout.addWidget(encrypt_button)

        decrypt_button = QPushButton("Decrypt File")
        decrypt_button.setIcon(QIcon.fromTheme("unlock"))
        decrypt_button.setStyleSheet(
            "font-size: 18px; padding: 15px; background-color: #FF5722; color: white;"  # Larger font size and padding
        )
        decrypt_button.clicked.connect(self.decrypt_file)
        button_layout.addWidget(decrypt_button)

        main_layout.addLayout(button_layout)

        # Footer
        footer_label = QLabel("Developed with ❤️ by Abhinandan Bais")
        footer_label.setStyleSheet("font-size: 16px; color: #999;")  # Larger font size
        footer_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(footer_label)

        # Set Main Layout
        self.setLayout(main_layout)

    def open_file(self):
        self.file_name, _ = QFileDialog.getOpenFileName(self, "Select File")
        if self.file_name:
            self.label.setText(f"Selected: {self.file_name}")
        else:
            self.label.setText("No file selected")

    def encrypt_file(self):
        if self.file_name and self.password_input.text():
            try:
                encrypt_file(self.file_name, self.password_input.text())
                QMessageBox.information(self, "Success", "File encrypted successfully!")
                self.label.setText("No file selected")
                self.password_input.clear()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")
        else:
            QMessageBox.warning(self, "Warning", "Please select a file and enter a password!")

    def decrypt_file(self):
        if self.file_name and self.password_input.text():
            try:
                decrypt_file(self.file_name, self.password_input.text())
                QMessageBox.information(self, "Success", "File decrypted successfully!")
                self.label.setText("No file selected")
                self.password_input.clear()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")
        else:
            QMessageBox.warning(self, "Warning", "Please select a file and enter a password!")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = EncryptionApp()
    window.show()
    sys.exit(app.exec_())