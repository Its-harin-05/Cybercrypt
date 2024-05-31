<h1>Cybercrypt</h1>
Applying Innovative Encryption for safeguarding Digital Information. This project implements a multi-layer encryption and decryption system using Monoalphabetic, Caesar Cipher, and RSA algorithms. 

<h2>Key Features</h2>

- **Monoalphabetic Encryption:**  Encrypts the message using a substitution cipher.

- **Caesar Cipher Encryption:** Applies a shift to the monoalphabetically encrypted message.

- **RSA Encryption:** Encrypts the Caesar cipher encrypted message using RSA.

- **Base64 Encoding:** Encodes the RSA encrypted message for safe transmission.

- **Decryption:** The reverse process of the above steps to retrieve the original message.

<h2>Technologies Used</h2>

- **Python 3.x:** The programming language used for the backend logic.

- **Flask:** A micro web framework for Python to handle HTTP requests.

- **PyCryptoDome:** A library for cryptographic operations (for RSA encryption).

- **Base64:** Python's standard library module for encoding and decoding Base64.

- **Frontend:** HTML/CSS/JavaScript: Standard web technologies used for creating the user interface

<h2>Getting Started</h2>

To run this process locally on your machine, follow these steps:

1. Clone the repository to your local machine.

```bash
git clone https://github.com/IPHive-24/Cybercrypt.git
```
```bash
cd Cybercrypt
```

2. Install Backend Dependencies:

```bash
pip install -r requirements.txt
```

3. Run the Flask application using
   
```bash
python app.py
```

<h2>Usage</h2>
<h3>Encryption</h3>

1. Run the Flask application using
   
```bash
python app.py
```

2. Open your browser and navigate

```bash
http://localhost:5000
```
3. Enter the message you want to encrypt, the shift value for Caesar cipher, and click on "Encrypt".

4. The encrypted message will be displayed in Base64 format.

<h3>Decryption</h3> 

1. Enter the encrypted Base64 message, the private RSA key, and the shift value used during encryption.

2. Click on "Decrypt".

3. The decrypted original message will be displayed.

<h2>Methodology</h2>
<h3>Encryption:</h3>

- **Monoalphabetic Encryption:** Applies a substitution cipher to the message.
  
- **Caesar Cipher Encryption:** Shifts the monoalphabetically encrypted message by a specified number of positions.
  
- **RSA Encryption:** Encrypts the Caesar cipher encrypted message using RSA.
  
- **Base64 Encoding:** Encodes the RSA encrypted message into a Base64 string for safe transmission.
  
<h3>Decryption:</h3>

- **Base64 Decoding:** Decodes the Base64 encoded encrypted message to binary data.
  
- **RSA Decryption:** Decrypts the binary data using the private RSA key.
  
- **Caesar Cipher Decryption:** Shifts the decrypted message back by the specified number of positions.
  
- **Monoalphabetic Decryption:** Reverses the substitution cipher to retrieve the original message.

<h2>Performance Evaluation</h2>  

The performance of this encryption-decryption system can be evaluated based on:

- Encryption and decryption speed.
  
- Accuracy of the decrypted message.
  
- Security of the multi-layer encryption approach.

<h2>Contribution</h2>

Contributions to the Cybercrypt project are welcome! If you have any ideas for improvements, feature requests, or bug reports, please feel free to open an issue or submit a pull request. Your contributions will help make the application more robust and beneficial for users.
  




