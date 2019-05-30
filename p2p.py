import time
import cherrypy
import nacl.encoding
import nacl.signing
import base64
import json
import urllib.request
import pprint
import nacl.utils
import nacl.secret
import time
import os.path
import database

class p2p():
    def __init__(self, username, password, signing_key):
        self.username = username
        self.password = password
        self.signing_key = signing_key

    def sendBroadcastMessage(self, message):
        headers = self.createAuthorisedHeader()
        loginserver_record = database.getUserInfo(self.username, "loginrecord")
        ts = str(time.time())
        message_bytes = bytes(loginserver_record+message+ts, encoding='utf-8')
        signed = self.signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')
        payload = {
            "loginserver_record": loginserver_record,
            "message": message,
            "sender_created_at": ts,
            "signature": signature_hex_str
        }

        print("GETTING PERSON")
        all_users = database.getAllUsers()
        print(all_users)

        for user in all_users:
            user_address = user.get("address", None)
            if user_address is None:
                continue
            url = "http://" + user_address + "/api/rx_broadcast"
            print(url)

            try:
                JSON_object = self.postJson(payload, headers, url)
                print(JSON_object)
                response = JSON_object.get("response", None)
                if response == "ok":
                    print("broadcast successfully sent")
                    print("url")
                else:
                    print("response not OK")
            except:
                print("FAILED TO BROADCAST!")
    
    def sendPrivateMessage(self, message, send_user):
        headers = self.createAuthorisedHeader()
        user = database.getUserData(send_user)
        user_address = user.get("address", None)
        user_location = user.get("location", None)
        user_pubkey = user.get("pubkey", None)
        
       
        encr_message = self.encryptMessage(message, user_pubkey)
        loginserver_record = database.getUserInfo(self.username, "loginrecord")        
        print(loginserver_record)
        ts = str(time.time())
        message_bytes = bytes(loginserver_record+user_pubkey+send_user+encr_message+ts, encoding='utf-8')
        signed = self.signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')

        payload = {
            "loginserver_record": loginserver_record,
            "target_pubkey": user_pubkey,
            "encrypted_message": encr_message,
            "target_username": send_user,
            "sender_created_at": ts,
            "signature": signature_hex_str
        }

        

        print("GETTING PERSON")
        print(user)
        if user_address is None:
            return 1
        url = "http://" + user_address + "/rx_privatemessage"
        #url = "http://cs302.kiwi.land/rx_privatemessage"
        print(payload)
        print(url)


        try:
            JSON_object = self.postJson(payload, headers, url)
            print(JSON_object)
            response = JSON_object.get("response", None)
            if response == "ok":
                print("pm sent successfully sent")
            else:
                print("response not OK")
        except:
            print("FAILED TO SEND ADMIN MESAGE")

    def encryptMessage(self, message, publickey_hex):
        #publickey_hex contains the target publickey
        #using the nacl.encoding.HexEncoder format
        verifykey = nacl.signing.VerifyKey(publickey_hex, encoder=nacl.encoding.HexEncoder)
        publickey = verifykey.to_curve25519_public_key()
        sealed_box = nacl.public.SealedBox(publickey)
        message_bytes = bytes(message, encoding='utf-8')
        encrypted = sealed_box.encrypt(message_bytes, encoder=nacl.encoding.HexEncoder)
        message_encr = encrypted.decode('utf-8')
        return message_encr
    '''
    returns an authorised header
    '''
    def createAuthorisedHeader(self):

        if self.username is None or self.password is None:
            return None
        #create HTTP BASIC authorization header
        credentials = ('%s:%s' % (self.username, self.password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }
        return headers

    '''
    sends a POST/GET request to the URL endpoint specified.
    returns the JSON response
    ''' 
    def postJson(self, payload, headers, url):

        if payload is not None:
            payload = json.dumps(payload).encode('utf-8')
        try:
            req = urllib.request.Request(url, data=payload, headers=headers)
            response = urllib.request.urlopen(req, timeout=5)
            data = response.read() # read the received bytes
            encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()
            return None #unneeded?
        
        JSON_object = json.loads(data.decode(encoding))
        return JSON_object

    
    

