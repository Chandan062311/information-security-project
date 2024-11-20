import os
from flask import Flask, render_template, request, redirect, url_for
from algorithms import (
    caesar_cipher,
    aes,
    des_cipher,
    rsa_cipher,
    sha1_hash,
    modified_algo
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        operation = request.form.get('operation')
        algorithm = request.form.get('algorithm')
        text = request.form.get('text')
        key = request.form.get('key')
        shift = request.form.get('shift')
        private_key = request.form.get('private_key')
        result = ''

        try:
            if operation == 'encrypt':
                if algorithm == 'caesar':
                    shift = int(request.form.get('shift', 3))
                    result = caesar_cipher.encrypt(text, shift)
                elif algorithm == 'aes':
                    result = aes.encrypt(text, key)
                elif algorithm == 'des':
                    result = des_cipher.encrypt(text, key)
                elif algorithm == 'rsa':
                    private_key, public_key = rsa_cipher.generate_keys()
                    result = rsa_cipher.encrypt(text, public_key)
                    # Store keys as needed
                elif algorithm == 'sha1':
                    result = sha1_hash.hash_text(text)
                elif algorithm == 'modified':
                    result = modified_algo.encrypt(text, key)
            elif operation == 'decrypt':
                if algorithm == 'caesar':
                    shift = int(request.form.get('shift', 3))
                    result = caesar_cipher.decrypt(text, shift)
                elif algorithm == 'aes':
                    result = aes.decrypt(text, key)
                elif algorithm == 'des':
                    result = des_cipher.decrypt(text, key)
                elif algorithm == 'rsa':
                    # You need to provide the private key for decryption
                    private_key = request.form.get('private_key', '')
                    result = rsa_cipher.decrypt(text, private_key)
                elif algorithm == 'modified':
                    result = modified_algo.decrypt(text, key)
                else:
                    result = "Decryption not supported for this algorithm."
        except Exception as e:
            result = f"Error: {str(e)}"

        return render_template('result.html', result=result)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=False)  # Set debug to False for production