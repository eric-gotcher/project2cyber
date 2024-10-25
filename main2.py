import sqlite3
import base64
import uuid
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, abort
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk, jwt
import os

print(os.getcwd())

app = Flask(__name__)

DATABASE = 'totally_not_my_privateKeys.db'

def createDb():
    """Create the SQLite database and the keys table."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def insertKeyIntoDb(key, expiry):
    """Insert a key into the database with its expiry."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (key, expiry))
    conn.commit()
    conn.close()

def getValidKeysFromDb(expired=False):
    """Retrieve keys from the database based on expiration status."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    now = int(datetime.utcnow().timestamp())
    if expired:
        cursor.execute('SELECT kid, key FROM keys WHERE exp <= ?', (now,))
    else:
        cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (now,))
    keys = cursor.fetchall()
    conn.close()
    return keys

def generateRsaKeyPair():
    """Generate RSA key pair."""
    privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    unencryptedPrivateKey = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return unencryptedPrivateKey

def storeNewKey():
    """Generate a new RSA key and store it in the database with an expiry."""
    key = generateRsaKeyPair()
    expiry = int((datetime.utcnow() + timedelta(hours=1)).timestamp())  # 1 hour expiry
    insertKeyIntoDb(key, expiry)

def storeExpiredKey():
    """Generate an expired RSA key and store it in the database."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    expiredPrivateKey = generateRsaKeyPair()

    expirationTime = int((datetime.utcnow() - timedelta(days=1)).timestamp())

    cursor.execute('''
        INSERT INTO keys (key, exp)
        VALUES (?, ?)
    ''', (expiredPrivateKey, expirationTime))

    conn.commit()
    conn.close()

def createJwtToken(privateKey, kid):
    """Create JWT token using the private key."""
    key = jwk.JWK.from_pem(privateKey)
    claims = {
        "sub": "user",
        "exp": (datetime.utcnow() + timedelta(hours=1)).timestamp()
    }
    token = jwt.JWT(header={"alg": "RS256", "kid": str(kid)}, claims=claims)
    token.make_signed_token(key)
    return token.serialize()

@app.route('/auth', methods=['POST'])
def auth():
    """Issue JWT signed by the private key from the database."""
    expired = request.args.get('expired')
    try:
        if expired:
            keyData = getValidKeysFromDb(expired=True)
        else:
            keyData = getValidKeysFromDb(expired=False)
        
        if not keyData:
            # Return a 404 response explicitly
            return jsonify({"message": "Key not found"}), 404

        kid, privateKey = keyData[0]
        token = createJwtToken(privateKey, kid)
        return jsonify({"token": token})

    except Exception as e:
        app.logger.error(f"Error in /auth: {e}")
        return jsonify({"message": "Internal server error"}), 500


@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """Return JWKS with valid public keys."""
    jwks = {'keys': []}
    try:
        validKeys = getValidKeysFromDb(expired=False)
        for kid, privateKey in validKeys:
            publicKey = serialization.load_pem_private_key(privateKey, password=None).public_key()
            jwkKey = jwk.JWK.from_pem(publicKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            jwks['keys'].append({
                'kid': str(kid),
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': base64.urlsafe_b64encode(publicKey.public_numbers().n.to_bytes(
                    (publicKey.public_numbers().n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
                'e': base64.urlsafe_b64encode(publicKey.public_numbers().e.to_bytes(
                    (publicKey.public_numbers().e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
            })

        return jsonify(jwks)
    except Exception as e:
        app.logger.error(f"Error in /.well-known/jwks.json: {e}")
        abort(500, description="Internal server error")

if __name__ == '__main__':
    # Initialize database and store keys
    createDb()
    storeNewKey()
    storeExpiredKey()
    # Start server
    app.run(port=8080, debug=True)