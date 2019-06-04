
import json
import urllib.request
import database
import time
import nacl.encoding
import nacl.signing
import base64
from nacl import pwhash, secret, utils
import nacl.hash

salt = b'\xa3\x95\\\xec\x1cFpr8\xb7\x92\x7f\x18%)\x88'

'''
sends a POST/GET request to the URL endpoint specified.
returns the JSON response
''' 
def postJson(payload, headers, url):

    if payload is not None:
        payload = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)

        response = urllib.request.urlopen(req, timeout=10)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
        return None #unneeded?
    
    JSON_object = json.loads(data.decode(encoding))
    return JSON_object

def verifyMessageSignature(messageString, pubkey, signatureString):
    signature_bytes = bytes(signatureString, encoding='utf-8')
    message= bytes(messageString, encoding='utf-8')
    message_bytes_hex = bytes(message.hex(),encoding='utf-8')
    pubkey_hex = bytes(pubkey,encoding='utf-8')
    verify_key = nacl.signing.VerifyKey(pubkey_hex, encoder=nacl.encoding.HexEncoder)
    verify_key.verify(message_bytes_hex, signature_bytes, encoder=nacl.encoding.HexEncoder)

def breakLoginRecord(loginserver_record):
    login_info = loginserver_record.split(',')
    username = login_info[0]
    pubkey = login_info[1]
    server_time = login_info[2]
    signature_str = login_info[3]
    return username, pubkey, server_time, signature_str

def generateResponseJSON(error):
    payload = {}
    if error == "ok":
        payload["response"] = "ok"
    else: 
        payload["response"] = "error"
        payload["message"] = error
    return payload

def getUserData(username):
    user = database.getUserData(username)
    user_address = user.get("address", None)
    user_location = user.get("location", None)
    user_pubkey = user.get("pubkey", None)
    return user_pubkey, user_address, user_location

def getShaHash(message):
    if isinstance(message, str):
        message = bytes(message, encoding='utf-8')
    hash = nacl.hash.sha256(message, encoder=nacl.encoding.HexEncoder)
    return hash

def AddToPrivateData(logserv, key, value):
    private_data = logserv.getPrivateData()
    values = private_data.get(key, None)
    if not values:
        values = []
    values.append(value)
    private_data[key] = values
    logserv.addPrivateData(private_data)

def encryptMessage(message, publickey_hex):
    #publickey_hex contains the target publickey
    #using the nacl.encoding.HexEncoder format
    verifykey = nacl.signing.VerifyKey(publickey_hex, encoder=nacl.encoding.HexEncoder)
    publickey = verifykey.to_curve25519_public_key()
    sealed_box = nacl.public.SealedBox(publickey)
    message_bytes = message
    if isinstance(message, str):
        message_bytes = bytes(message, encoding='utf-8')
    encrypted = sealed_box.encrypt(message_bytes, encoder=nacl.encoding.HexEncoder)
    message_encr = encrypted.decode('utf-8')
    return message_encr

def getSymmetricKeyFromPassword(password):
    password = bytes(password, encoding='utf-8')
    kdf = pwhash.argon2i.kdf
    ops = pwhash.argon2i.OPSLIMIT_SENSITIVE
    mem = pwhash.argon2i.MEMLIMIT_SENSITIVE
    key = kdf(secret.SecretBox.KEY_SIZE, password, salt, opslimit=ops, memlimit=mem)
    return key

def generateRandomSymmetricKey():
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    return key

'''
takes in a string as input, and encrypts it with the SecretBox
'''
def encryptStringKey(key, input):
    input_bytes = bytes(input, encoding='utf-8')     
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(input_bytes, nonce)

    return encrypted

'''
takes in an encrypted messge, and returns a decryped version (string)
'''
#TODO: error message when the key cannot decrypt the message.
def decryptStringKey(key, input):  
    box = nacl.secret.SecretBox(key)
    plaintext = box.decrypt(input) #should be bytes
    data = plaintext.decode("utf-8") 

    return data


