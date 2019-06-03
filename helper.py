
import json
import urllib.request
import database
import time
import nacl.encoding
import nacl.signing

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