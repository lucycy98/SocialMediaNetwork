
import json
import urllib.request
import database
import time
import nacl.encoding
import nacl.signing
import base64
from nacl import pwhash, secret, utils
import nacl.hash
from datetime import datetime

'''
this class contains helper methods used by other classes
'''

'''
checks the database whether the username is blocked or not  
''' 
def checkValidUser(username, usernameToCheck):
    blockedUsers = database.getBlockedUser(username)
    for user in blockedUsers:
        if usernameToCheck == user["blockedUser"]:
            return False
    return True


'''
checks against db whether a message contains a blocked word  
'''
def checkValidMessage(username, message):
    blockedWords = database.getBlockedWords(username)
    for word in blockedWords:
        blockedWord = word["word"]
        if blockedWord in message:
            return False
    return True

'''
checks against db whether broadcast signature has been blocked by user  
'''
def checkValidBroadcast(username, signature):
    broadcasts = database.getBlockedBroadcasts(username)
    for broadcast in broadcasts:
        if signature == broadcast["signature"]:
            return False
    return True

'''
checks against db whether bc has been blocked by anyone
'''
def checkValidBroadcastAll(signature):
    broadcasts = database.getAllBlockedBroadcasts()
    for broadcast in broadcasts:
        if signature == broadcast["signature"]:
            return False
    return True

'''
sends a POST/GET request to the URL endpoint specified.
returns the JSON response
''' 
def addMetaData(key,value,username):
    if key == "favourite_broadcast":
        database.addFavBroadcast(username, value)
    elif key == "block_broadcast":
        database.addBlockedBroadcast(username, value)
    elif key == "block_username":
        database.addBlockedUser(username, value)
    elif key == "block_pubkey":
        #TODO add pubkey ?????????
        print("someone added a pubkey")

'''
used to post send a url request with headers and payload
returns the response, if error: returns error
'''
def postJson(payload, headers, url):

    if payload is not None:
        payload = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req, timeout=3)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        return {"response": "error", "message": error.reason } 
    else:
        JSON_object = json.loads(data.decode(encoding))
        return JSON_object

'''
checks signature was signed with the right key and was not forged
will raise an exception is forged
'''
def verifyMessageSignature(messageString, pubkey, signatureString):
    signature_bytes = bytes(signatureString, encoding='utf-8')
    message= bytes(messageString, encoding='utf-8')
    message_bytes_hex = bytes(message.hex(),encoding='utf-8')
    pubkey_hex = bytes(pubkey,encoding='utf-8')
    verify_key = nacl.signing.VerifyKey(pubkey_hex, encoder=nacl.encoding.HexEncoder)
    verify_key.verify(message_bytes_hex, signature_bytes, encoder=nacl.encoding.HexEncoder)

'''
breaks down login record  
'''
def breakLoginRecord(loginserver_record):
    login_info = loginserver_record.split(',')
    username = login_info[0]
    pubkey = login_info[1]
    server_time = login_info[2]
    signature_str = login_info[3]
    return username, pubkey, server_time, signature_str

'''
    generates response for incoming api
'''
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

'''
adss to private data in login server    
'''
def addToPrivateData(logserv, key, value):
    private_data = logserv.getPrivateData()
    values = private_data.get(key, None)
    if not values:
        values = []
    values.append(value)
    private_data[key] = values
    logserv.addPrivateData(private_data)

'''
encrypts message using pubkey
'''
def encryptMessage(message, publickey_hex):

    verifykey = nacl.signing.VerifyKey(publickey_hex, encoder=nacl.encoding.HexEncoder)
    publickey = verifykey.to_curve25519_public_key()
    sealed_box = nacl.public.SealedBox(publickey)
    message_bytes = message
    if isinstance(message, str):
        message_bytes = bytes(message, encoding='utf-8')
    encrypted = sealed_box.encrypt(message_bytes, encoder=nacl.encoding.HexEncoder)
    message_encr = encrypted.decode('utf-8')
    return message_encr
'''
decrypts message using private key
'''
def decryptMessage(message, privatekey):
    key = privatekey.to_curve25519_private_key()
    sealed_box = nacl.public.SealedBox(key)
    message_bytes = message
    if isinstance(message, str):
        message_bytes = bytes(message, encoding='utf-8')
    decrypted = sealed_box.decrypt(message_bytes, encoder=nacl.encoding.HexEncoder)
    #decrypted_message = decrypted.decode('utf-8')
    return decrypted

def getSymmetricKeyFromPassword(password):
    password = bytes(password, encoding='utf-8')
    long_salt = nacl.pwhash.argon2i.SALTBYTES * password
    salt = long_salt[0:nacl.pwhash.argon2i.SALTBYTES]
    kdf = pwhash.argon2i.kdf
    ops = pwhash.argon2i.OPSLIMIT_SENSITIVE
    mem = pwhash.argon2i.MEMLIMIT_SENSITIVE
    key = kdf(secret.SecretBox.KEY_SIZE, password, salt=salt, opslimit=ops, memlimit=mem)
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
def decryptStringKey(key, inputBytes):  
    if isinstance(inputBytes, str):
        inputBytes = bytes(inputBytes, encoding='utf-8')

    box = nacl.secret.SecretBox(key)
    plaintext = box.decrypt(inputBytes) #should be bytes
    data = plaintext.decode("utf-8") 

    return data

def formatTime(unix):
    ts = int(unix)
    dateobj = datetime.fromtimestamp(ts).strftime('%d/%m/%Y %H:%M %p')
    return dateobj

def getEncryptionKey(logserv,groupkey_hash):
    private_data = logserv.getPrivateData()
    prikeys = private_data.get("prikeys", None)
    for prikey_str in prikeys:
        prikey = bytes.fromhex(prikey_str)
        hash_key = getShaHash(prikey)
        print("hashkey is")
        print(hash_key)
        if hash_key == groupkey_hash:
            return prikey
    return None

def bytestoStringNacl(bytes_input):
    bytes_hex = bytes_input.hex()
    bytes_hex_str = bytes_hex.decode('utf-8')
    return bytes_hex_str

    



