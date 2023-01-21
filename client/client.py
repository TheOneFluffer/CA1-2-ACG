#------------------------------------------------------------------------------------------
# Client.py
#------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please starts the tcp server first before running this client
 
import datetime
import sys              # handle system error
import socket
import time
import base64
from Cryptodome import Random
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import pad
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Cipher import AES, PKCS1_OAEP
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


global host, port

host = socket.gethostname()
port = 8888         # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu.csv"
return_file = "day_end.csv"

# ---------------- generate key ---------------
st_cert=open('client.der','rb').read()          # Public key
cert = x509.load_der_x509_certificate(st_cert, default_backend())
clientPubKey = cert.public_key()
clientPubKey = clientPubKey.public_bytes(Encoding.PEM,format=PublicFormat.PKCS1)

x509pem = open('client.key', 'r').read()        # Private key
clientPrivKey = RSA.import_key(x509pem)

# ---------------- user defined functions ------------
def encrypt_public_key(key, data):
    encryptor = PKCS1_OAEP.new(key)
    encrypted_msg = encryptor.encrypt(data)
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg


def aes_cbc_encrypt(key, data, IV):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    data = pad(data, AES.block_size)
    return cipher.encrypt(data) 



# ---------------- main programme ---------------------

key = Random.get_random_bytes(16)                   # AES-128 selected
IV = Random.new().read(AES.block_size)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_GET_MENU )  

    data = my_socket.recv(4096)
    #hints : need to apply a scheme to verify the integrity of data.  
    menu_file = open(menu_file,"wb")
    menu_file.write( data)
    menu_file.close()
    my_socket.close()

print('Menu today received from server')
#print('Received', repr(data))  # for debugging use
my_socket.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_END_DAY)

    # RSA 

    serverPubKey = RSA.import_key(my_socket.recv(4096))                  # Exchange public keys
    print("Server Public Key Received.")
    encrypted_aes_key = encrypt_public_key(serverPubKey, key)
    my_socket.send(clientPubKey)
    print("Client Public Key Sent.")
    time.sleep(1)
    my_socket.send(encrypted_aes_key)
    print("Encrypted AES Key Sent.")
    time.sleep(1)
    my_socket.send(IV)
    print("Initialisation Vector Sent.")  

    try:
        out_file = open(return_file,"rb")
    except:
        print("file not found : " + return_file)
        sys.exit(0)
    file_bytes = out_file.read(1024)
    sent_bytes=b''
    while file_bytes != b'':
        # hints: need to protect the file_bytes in a way before sending out.
        my_socket.send(file_bytes)
        sent_bytes+=file_bytes
        file_bytes = out_file.read(1024) # read next block from file
    out_file.close()
    my_socket.close()
print('Sale of the day sent to server')
#print('Sent', repr(sent_bytes))  # for debugging use
my_socket.close()
