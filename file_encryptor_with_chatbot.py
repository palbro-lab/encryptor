import os
import base64
from flask import Flask, request, render_template, send_file, jsonify
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Flask App
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
RESULT_FOLDER = 'results'

# Ensure folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

def derive_key_from_password(password, salt=b'static_salt', iterations=100_000):
    """Derive a cryptographic key from a password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return Fernet(key)

@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Encrypt a file using a password-derived key."""
    file = request.files.get('file')
    password = request.form.get('password')
    if file and password:
        cipher = derive_key_from_password(password)
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        with open(filepath, 'rb') as f:
            encrypted_data = cipher.encrypt(f.read())

        encrypted_filename = f"{os.path.splitext(file.filename)[0]}_encrypted{os.path.splitext(file.filename)[1]}"
        result_path = os.path.join(RESULT_FOLDER, encrypted_filename)

        with open(result_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        return send_file(result_path, as_attachment=True)

    return "File and password are required."

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypt a file using a password-derived key."""
    file = request.files.get('file')
    password = request.form.get('password')
    if file and password:
        cipher = derive_key_from_password(password)
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        with open(filepath, 'rb') as f:
            try:
                decrypted_data = cipher.decrypt(f.read())
            except Exception:
                return "Decryption failed. Ensure the password is correct and the file is valid."

        decrypted_filename = f"{os.path.splitext(file.filename)[0]}_decrypted{os.path.splitext(file.filename)[1]}"
        result_path = os.path.join(RESULT_FOLDER, decrypted_filename)

        with open(result_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        return send_file(result_path, as_attachment=True)

    return "File and password are required."

@app.route('/chatbot', methods=['POST'])
def chatbot():
    """Handle chatbot interactions."""
    user_input = request.json.get('message', '').lower()
    if 'encrypt' in user_input:
        return jsonify(response="To encrypt a file, upload the file and set a password. Use the Encrypt File option.")
    elif 'decrypt' in user_input:
        return jsonify(response="To decrypt a file, upload the encrypted file and provide the same password used for encryption.")
    elif 'password' in user_input:
        return jsonify(response="The password is used to generate a secure key for encryption and decryption. Make sure you remember it!")
    else:
        return jsonify(response="I'm here to assist with file encryption and decryption tasks. How can I help?")

if __name__ == '__main__':
    app.run(debug=True)
