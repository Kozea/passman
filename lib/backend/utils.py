from base64 import b64decode, b64encode
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def decrypt_private_key(user, input_password):
    encrypted_private_key = b64decode(user.private_key)
    nonce = b64decode(user.nonce)
    hash_object = SHA256.new(data=input_password.encode('utf-8'))
    cipher = ChaCha20.new(key=hash_object.digest(), nonce=nonce)

    return cipher.decrypt(encrypted_private_key)


def decrypt_password(password, session_key):
    items = {
        'login': ['login_nonce', 'login_tag'],
        'password': ['password_nonce', 'password_tag'],
        'questions': ['questions_nonce', 'questions_tag'],
    }

    for item in items:
        item_attr = items[item]
        nonce = b64decode(getattr(password, item_attr[0]))
        tag = b64decode(getattr(password, item_attr[1]))
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        items[item] = b64encode(cipher_aes.decrypt_and_verify(
            b64decode(getattr(password, item)), tag)).decode('utf-8')

    return items


def decrypt_passwords(passwords, private_key):
    rsa_private_key = RSA.import_key(private_key)

    passwords_decrypted = {}

    for password in passwords:
        cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
        session_key = cipher_rsa.decrypt(b64decode(password.session_key))
        passwords_decrypted[password.label] = decrypt_password(password, session_key)

    return passwords_decrypted
