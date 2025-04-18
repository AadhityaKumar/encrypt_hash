import sys
import os
import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


def AES(data, p, m):

    if(p == 1):
        key = os.urandom(32)
    else:
        key = os.urandom(16)

    initializationVector = os.urandom(16)
    if(m == 1):
        cipher = Cipher(algorithms.AES(key), modes.CBC(initializationVector))
    else:
        cipher = Cipher(algorithms.AES(key), modes.ECB())

    encrypt = cipher.encryptor()

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipherText = encrypt.update(padded_data) + encrypt.finalize()
    return cipherText, key, initializationVector



def AES_decrypt(data, key, initializationVector, m):
    
    if(m == 1):
        cipher = Cipher(algorithms.AES(key), modes.CBC(initializationVector))
    else:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
    
    decrypt = cipher.decryptor()

    plainText = decrypt.update(data) + decrypt.finalize()

    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(plainText) + unpadder.finalize()

    return unpadded_data



def Hashee(data):
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(data)
    digest = hasher.finalize()
    st.info(digest.hex())

def RSA_encrypt(plaintext, public_key):
    ciphertext = public_key.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label = None))
    return ciphertext

def RSA_decrypt(ciphertext, private_key):
    plainText = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label = None))
    return plainText



selection = st.radio("Select operation: ", ["Hash a file", "Encrypt message (RSA)", "Decrypt message (RSA)", "Encrypt message (AES)", "Decrypt message(AES)"])

if 'privateKey' not in st.session_state:
    st.session_state.privateKey = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
    st.session_state.publicKey = st.session_state.privateKey.public_key()

#data = b"absss"

if(selection == "Encrypt message (AES)"):

    p = st.file_uploader("Choose a file")

    if p:
        data = bytearray(p.read())
        ct, st.session_state.k, st.session_state.iv = AES(data, 0, 0)
        st.info("Ciphertext is: " + str(ct))
        st.info("Key is: " + str(st.session_state.k))

elif(selection == "Hash a file"):

    p = st.file_uploader("Choose a file")
    data = bytearray(p.read())
    Hashee(data)

elif(selection == "Encrypt message (RSA)"):

    p = st.file_uploader("Choose a file")

    if p:
        data = p.read()
        n = RSA_encrypt(data, st.session_state.publicKey)

        st.download_button("Download Encrypted File", data=n, file_name="encrypted.bin")
        st.info("Public and Private keys are saved to system")
    
elif(selection == "Decrypt message (RSA)"):

    data = st.file_uploader("Enter the encrypted file")
    ext = st.text_input("Enter the file extension")
    fn = "decrypted." + ext

    if data and ext:
        xx = RSA_decrypt(data, st.session_state.privateKey)
        st.download_button("Decrypted file: ", data = bytes(xx), file_name = fn)

elif(selection == "Decrypt message(AES)"):
    
    data = st.text_input("Enter the cipherText")
    ke = st.text_input("Enter the key")
    extt = st.text_input("Enter the file extension")
    fnn = "decrypted." + extt

    if data and ke and extt:
        br = AES_decrypt(data, ke, st.session_state.iv, 0)
        st.download_button("Decrypted file: ", data = bytes(br), file_name = fnn)






