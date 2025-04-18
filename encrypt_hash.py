import base64
import os
import random
import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


def AES(data, p, m, initializationVector):

    if(p == 1):
        key = os.urandom(32)
    else:
        key = os.urandom(16)

    if(m == 1):
        cipher = Cipher(algorithms.AES(key), modes.CBC(initializationVector))
    else:
        cipher = Cipher(algorithms.AES(key), modes.ECB())

    encrypt = cipher.encryptor()

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipherText = encrypt.update(padded_data) + encrypt.finalize()
    return cipherText, key


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


def T_DES_enc(data, p, m, initializationVector):

    if(p == 1):
        key = os.urandom(24)
    else:
        key = os.urandom(16)

    if(m == 1):
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(initializationVector))
    else:
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB())

    encrypt = cipher.encryptor()

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipherText = encrypt.update(padded_data) + encrypt.finalize()
    return cipherText, key

def T_DES_dec(data, key, initializationVector, m):
    if(m == 1):
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(initializationVector))
    else:
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB())
    
    decrypt = cipher.decryptor()

    plainText = decrypt.update(data) + decrypt.finalize()

    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(plainText) + unpadder.finalize()

    return unpadded_data


def generatePassword():

    gen_pass = []
    lc_alphabet = "abcdefghijklmnopqrstuvwxyz"
    uc_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numbers = "1234567890"
    symbols = "!@#$%^&*"

    for i in range (20):
        x = random.randint(0, 3)

        if x == 0:
            gen_pass.append(lc_alphabet[random.randint(0, 25)])
        if x == 1:
            gen_pass.append(uc_alphabet[random.randint(0, 25)])
        if x == 2:
            gen_pass.append(numbers[random.randint(0, 9)])
        if x == 3:
            gen_pass.append(symbols[random.randint(0, 7)])
    
    return gen_pass





def Hashee(data):
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(data)
    digest = hasher.finalize()
    return digest.hex()

def RSA_encrypt(plaintext, public_key):
    ciphertext = public_key.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label = None))
    return ciphertext

def RSA_decrypt(ciphertext, private_key):
    plainText = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label = None))
    return plainText

if 'initializationVector' not in st.session_state:
    st.session_state.initializationVector = os.urandom(16)


if 'initializationVector_3DES' not in st.session_state:
    st.session_state.initializationVector_3DES = os.urandom(8)

if "u_names" not in st.session_state:
    st.session_state.u_names = []
    st.session_state.pswds = []

selecter = st.radio("Select: ", ["Login", "Register"])

if selecter == "Login":

    userName = st.text_input("enter username")
    passWord = st.text_input("enter password")

    if(userName in st.session_state.u_names and Hashee(passWord.encode()) == st.session_state.pswds[st.session_state.u_names.index(userName)]):

        selection = st.radio("Select operation: ", ["Hash a file", "Encrypt message (RSA)", "Decrypt message (RSA)", 
        "Encrypt message (AES)", "Decrypt message(AES)", "Encrypt message (3DES)", "Decrypt message (3DES)"])

        if 'privateKey' not in st.session_state:
            st.session_state.privateKey = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
            st.session_state.publicKey = st.session_state.privateKey.public_key()




        if(selection == "Encrypt message (AES)"):

            p = st.file_uploader("Choose a file")
            v = st.number_input("Block mode (1 if CBC, 0 if ECB)", value = 0)
            keySize = st.number_input("Key_size (1 if 256, 0 if 128)", value = 0)

            if p:
                data = p.read()
                ct, keyer = AES(data, keySize, v, st.session_state.initializationVector)
                st.session_state.k = base64.b64encode(keyer).decode()

                st.download_button("Download Encrypted File (Copy key first)", data=ct, file_name="encrypted.bin")
                st.info("Key is: " + str(st.session_state.k))
        
        elif(selection == "Encrypt message (3DES)"):

            p = st.file_uploader("Choose a file")
            v = st.number_input("Block mode (1 if CBC, 0 if ECB)", value = 0)
            keySize = st.number_input("Key_size (1 if 192, 0 if 128)", value = 0)

            if p:
                data = p.read()
                ct, keyer = T_DES_enc(data, keySize, v, st.session_state.initializationVector_3DES)
                st.session_state.k = base64.b64encode(keyer).decode()

                st.download_button("Download Encrypted File (Copy key first)", data=ct, file_name="encrypted.bin")
                st.info("Key is: " + str(st.session_state.k))


        elif(selection == "Hash a file"):

            p = st.file_uploader("Choose a file")

            if p:
                data = bytearray(p.read())
                hx = Hashee(data)
                st.info(hx)


        elif(selection == "Encrypt message (RSA)"):

            p = st.file_uploader("Choose a file")

            if p:
                data = p.read()
                n = RSA_encrypt(data, st.session_state.publicKey)

                st.download_button("Download Encrypted File", data=n, file_name="encrypted.bin")
                st.info("Public and Private keys are saved to system")
            
        elif(selection == "Decrypt message (RSA)"):

            dat = st.file_uploader("Enter the encrypted file")
            if dat:
                data = dat.read()
            ext = st.text_input("Enter the file extension")
            fn = "decrypted." + ext

            if data and ext:
                xx = RSA_decrypt(data, st.session_state.privateKey)
                st.download_button("Decrypted file: ", data = bytes(xx), file_name = fn)

        elif(selection == "Decrypt message(AES)"):
            
            dar = st.file_uploader("Enter the encrypted file")
            vv = st.number_input("Block mode (1 if CBC, 0 if ECB)", value = 0)


            if dar:
                data = dar.read()

            ke = st.text_input("Enter the key")

            extt = st.text_input("Enter the file extension")
            fnn = "decrypted." + extt

            if data and ke and extt:

                kb = base64.b64decode(ke)
                br = AES_decrypt(data, kb, st.session_state.initializationVector, vv)
                st.download_button("Decrypted file: ", data = br, file_name = fnn)
        
        elif(selection == "Decrypt message (3DES)"):
            
            dar = st.file_uploader("Enter the encrypted file")
            vvv = st.number_input("Block mode (1 if CBC, 0 if ECB)", value = 0)


            if dar:
                data = dar.read()

            ke = st.text_input("Enter the key")

            extt = st.text_input("Enter the file extension")
            fnn = "decrypted." + extt

            if data and ke and extt:

                kb = base64.b64decode(ke)
                br = T_DES_dec(data, kb, st.session_state.initializationVector_3DES, vvv)
                st.download_button("Decrypted file: ", data = br, file_name = fnn)

    else:
        st.error("incorrect username or password")

elif(selecter == "Register"):

    unm = st.text_input("Enter username")
    ps = st.text_input("Enter password")

    c = st.checkbox("generate password?")

    if c:
        gp = generatePassword()
        st.info("".join(gp))

    if unm and ps:
        if unm not in st.session_state.u_names:
            st.session_state.u_names.append(unm)
            st.session_state.pswds.append(Hashee(ps.encode()))
            st.success("Account created")
        else:
            st.error("Username already exists")



