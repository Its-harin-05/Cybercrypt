from flask import Flask, render_template, request, jsonify, send_file
import rsa 
from rsa import PrivateKey
import base64  

from flask_cors import CORS

app = Flask(__name__)
CORS(app) 



# monoalphabetic key generating
def generate_cipher_key():
    substitution_key = {
        'a': 'X', 'b': 'Y', 'c': 'Z', 'd': 'A', 'e': 'B', 'f': 'C', 'g': 'D', 'h': 'E', 'i': 'F', 'j': 'G',
        'k': 'H', 'l': 'I', 'm': 'J', 'n': 'K', 'o': 'L', 'p': 'M', 'q': 'N', 'r': 'O', 's': 'P', 't': 'Q',
        'u': 'R', 'v': 'S', 'w': 'T', 'x': 'U', 'y': 'V', 'z': 'W', 'A': 'x', 'B': 'y', 'C': 'z', 'D': 'a',
        'E': 'b', 'F': 'c', 'G': 'd', 'H': 'e', 'I': 'f', 'J': 'g', 'K': 'h', 'L': 'i', 'M': 'j', 'N': 'k',
        'O': 'l', 'P': 'm', 'Q': 'n', 'R': 'o', 'S': 'p', 'T': 'q', 'U': 'r', 'V': 's', 'W': 't', 'X': 'u',
        'Y': 'v', 'Z': 'w', ' ': ' '
    }
    return substitution_key

# monoalphabetic encryption
def mono_encrypt(message, key):
    encrypted_message = ''
    for char in message:
        if char in key:
            encrypted_message += key[char]
        else:
            encrypted_message += char
    return encrypted_message

# monoalphabetic decryption
def mono_decrypt(ciphertext, key):
    reverse_key = {v: k for k, v in key.items()}
    decrypted_message = ''
    for char in ciphertext:
        if char in reverse_key:
            decrypted_message += reverse_key[char]
        else:
            decrypted_message += char
    return decrypted_message

# caeser encryption
def caesar_cipher_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            # Determine the appropriate shift for uppercase and lowercase letters
            if char.isupper():
                encrypted_char = chr((ord(char) - 65 + shift) % 26 + 65)
            else:
                encrypted_char = chr((ord(char) - 97 + shift) % 26 + 97)
        else:
            encrypted_char = char  # Preserve non-alphabetic characters
        encrypted_text += encrypted_char
    return encrypted_text

# caeser decryption
def caesar_cipher_decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            # Determine the appropriate shift for uppercase and lowercase letters
            if char.isupper():
                decrypted_char = chr((ord(char) - 65 - shift) % 26 + 65)
            else:
                decrypted_char = chr((ord(char) - 97 - shift) % 26 + 97)
        else:
            decrypted_char = char  # Preserve non-alphabetic characters
        decrypted_text += decrypted_char
    return decrypted_text

# key generating for rsa
def generate_key_pair():
    public_key, private_key = rsa.newkeys(2048)
    public_key_path = r"C:\Users\jaikr\Music\encryption\public_key.pem"
    private_key_path = r"C:\Users\jaikr\Music\encryption\private_key.pem"
    
    
    with open(public_key_path, "wb") as f:
        f.write(public_key.save_pkcs1("PEM"))
        
    with open(private_key_path, "wb") as f:
        f.write(private_key.save_pkcs1("PEM"))
    
    return public_key_path, private_key_path

'''def save_keys(public_key, private_key, public_key_path, private_key_path):
    with open(public_key_path, 'wb') as file:
        file.write(public_key.save_pkcs1(format='PEM'))

    with open(private_key_path, 'wb') as file:
        file.write(private_key.save_pkcs1(format='PEM'))'''

# rsa encryption
def encrypt_message(message, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
        
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    return encrypted_message



@app.route('/')
def index():
    return render_template('Userin.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    message = str(request.form['message'])
    shiftkey = int(request.form['shift'])
    substitution_key = generate_cipher_key()
    
    mono_encrypted_message = mono_encrypt(message, substitution_key)
    print("mono_encrypted:", mono_encrypted_message)
    
    caesar_encrypted_message = caesar_cipher_encrypt(mono_encrypted_message, shiftkey)
    print("caeser_encrypted:",caesar_encrypted_message)
    
    public_key_path, _ = generate_key_pair()
    rsa_encrypted_message = encrypt_message(caesar_encrypted_message, public_key_path)
    print("rsa_enc:", rsa_encrypted_message)
    
    encoded_encrypted_message = base64.b64encode(rsa_encrypted_message)
    print("base64 enc:", encoded_encrypted_message)
    # Return the encrypted message as response
    return encoded_encrypted_message

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        # Receive encrypted content and private key from the client
        encoded_encrypted_message = request.form['encoded_encrypted_message']
        private_key_str = request.form['private_key']
        shift_value = request.form['shift_value']

        print("Received encoded encrypted message:", encoded_encrypted_message)
        print("Received private key:", private_key_str)
        print("Received shift value:", shift_value)



        # Load the private key from file
        with open("private_key.pem", "rb") as f:
            private_key_str = f.read()
            private_key = rsa.PrivateKey.load_pkcs1(private_key_str)

        # Decrypt with private key (RSA)
        encrypted_content_bytes = base64.b64decode(encoded_encrypted_message)
        print("encrypted_content_bytes :", encrypted_content_bytes)
        
        decrypted_rsa = rsa.decrypt(encrypted_content_bytes, private_key)

        print("Decrypted with RSA:", decrypted_rsa)
        
        decrypted_rsa_str = decrypted_rsa.decode()
        
        # Decrypt with Caesar shift value
        decrypted_caesar = caesar_cipher_decrypt(decrypted_rsa_str, int(shift_value))
        
        print("Decrypted with Caesar:", decrypted_caesar)

        # Reverse Monoalphabetic Encryption
        substitution_key = generate_cipher_key()
        decrypted_mono = mono_decrypt(decrypted_caesar, substitution_key)

        print("Decrypted Text:", decrypted_mono)

        # Return the decrypted result to the client
        return jsonify({'decrypted_text': decrypted_mono})

    except Exception as e:
        print("Decryption Error:", str(e))
        return jsonify({'error': str(e)})



@app.route('/generate_key_pair', methods=['GET'])
def generate_key_pair_route():
    public_key_path, private_key_path = generate_key_pair()
    with open(public_key_path, "rb") as f:
        public_key_str = f.read().decode()
    with open(private_key_path, "rb") as f:
        private_key_str = f.read().decode()
    return jsonify({'publicKey':public_key_str, 'privateKey':private_key_str})


if __name__ == "__main__":
    app.run(debug=True)


   