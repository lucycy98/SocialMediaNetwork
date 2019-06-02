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
import helper

class p2p():
    def __init__(self, username, password, signing_key):
        self.username = username
        self.password = password
        self.signing_key = signing_key
        self.apikey = None


    def broad(self,message):
        headers = self.createAuthorisedHeader(True)
        loginserver_record = database.getUserInfo(self.username, "loginrecord")
        ts = str(time.time())
        print(message)
        print(self.username)
        print(loginserver_record)
        message_bytes = bytes(loginserver_record+message+ts, encoding='utf-8')
        signed = self.signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')
        payload = {
            "loginserver_record": loginserver_record,
            "message": message,
            "sender_created_at": ts,
            "signature": signature_hex_str
        }

        print(payload)

        print("GETTING PERSON")
        all_users = database.getAllUsers()
        print(all_users)

        for user in all_users:
            user_address = user.get("address", None)
            if user_address is None:
                continue
            if user.get("username") == 'admin':
                url = "http://cs302.kiwi.land/api/rx_broadcast"
            else: 
                url = "http://" + user_address + "/api/rx_broadcast"
            print(url)

            try:
                JSON_object = helper.postJson(payload, headers, url)
                print(JSON_object)
                response = JSON_object.get("response", None)
                if response == "ok":
                    print("broadcast successfully sent")
                    print("url")
                else:
                    print("response not OK")
            except Exception as e:
                print("FAILED TO BROADCAST!")
                print(e)

    def sendBroadcastMessage(self, message):
        headers = self.createAuthorisedHeader(True)
        loginserver_record = database.getUserInfo(self.username, "loginrecord")
        ts = str(time.time())
        print(message)
        print(self.username)
        print(loginserver_record)
        message_bytes = bytes(loginserver_record+message+ts, encoding='utf-8')
        signed = self.signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')
        
        payload = {
            "loginserver_record": loginserver_record,
            "message": str(message),
            "sender_created_at": ts,
            "signature": signature_hex_str
        }

        print(payload)

        print("GETTING PERSON")
        
        url = "http://cs302.kiwi.land/api/rx_broadcast"
           
        try:
            JSON_object = helper.postJson(payload, headers, url)
            print(JSON_object)
            response = JSON_object.get("response", None)
            if response == "ok":
                print("broadcast successfully sent")
                print("url")
            else:
                print("response not OK")
        except Exception as e:
            print("FAILED TO BROADCAST!")
            print(e)
    
    def sendPrivateMessage(self, message, send_user):
        headers = self.createAuthorisedHeader(True)
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

        database.addsentMessages(self.username, send_user, message, ts) #TODO change so that it only loads if sent properly.

        print("GETTING PERSON")
        print(user)
        if user_address is None:
            return 1
        #url = "http://" + user_address + "/rx_privatemessage"
        url = "http://cs302.kiwi.land/rx_privatemessage"
        print(payload)
        print(url)

        try:
            JSON_object = helper.postJson(payload, headers, url)
            print(JSON_object)
            response = JSON_object.get("response", None)
            if response == "ok":
                print("pm sent successfully sent")
            else:
                print("response not OK")
        except:
            print("FAILED TO SEND ADMIN MESAGE")
    
    def retrieveMessages(self, username):
        print(username)
        theirMessages = database.getSpecificMessages(self.username, username) #message and timestamp
        print(theirMessages)
        myMessages = database.getAllSentMessages(self.username, username) #message and timestamp
        print(myMessages)

        all_messages = []


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
    def createAuthorisedHeaderOLD(self):

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

    def createAuthorisedHeader(self, needsAuthentication):

        if not needsAuthentication:
            headers = {
                'Content-Type' : 'application/json; charset=utf-8'
            }
            return headers

        if self.username is None or self.password is None:
            return None
    
        if self.apikey is None:
            with open('tmp/api.txt', "r") as f:
                self.apikey = f.read()

        print(self.apikey)       
        #create HTTP BASIC authorization header
        if self.apikey is not None: #change!!! TODO
            headers = {
                'X-username': self.username,
                'X-apikey' : self.apikey,
                'Content-Type' : 'application/json; charset=utf-8',
            }
        else:
            credentials = ('%s:%s' % (self.username, self.password))
            b64_credentials = base64.b64encode(credentials.encode('ascii'))
            headers = {
                'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
                'Content-Type' : 'application/json; charset=utf-8',
            }
        return headers
    
    

