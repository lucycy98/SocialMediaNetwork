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
    def __init__(self, username, password, signing_key, api, logserv):
        self.logserv = logserv
        self.username = username
        self.password = password
        self.signing_key = signing_key
        self.apikey = api

    def sendBroadcastMessage(self, message):
        headers = self.createAuthorisedHeader(True)
        print(headers)
        print(message)
        loginserver_record = database.getUserInfo(self.username, "loginrecord")
        ts = str(time.time())
        message_bytes = bytes(loginserver_record+message+ts, encoding='utf-8')
        signed = self.signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        print("signed")
        print(signed.signature)
        print(signed.message)
        signature_hex_str = signed.signature.decode('utf-8')
        
        
        payload = {
            "loginserver_record": loginserver_record,
            "message": message,
            "sender_created_at": ts,
            "signature": signature_hex_str
        }

        username, pubkey, server_time, signature_str = helper.breakLoginRecord(loginserver_record)

        database.addBroadCast(loginserver_record, message, ts, signature_hex_str, username)
    
        all_users = database.getAllUsers()

        for user in all_users:
            user_address = user.get("address", None)
            user_status = user.get("status", None)
            if user_address is None or user_status != "online":
                continue
            url = "http://" + user_address + "/api/rx_broadcast"
            
            if user.get("username") == 'admin':
                url = "http://cs302.kiwi.land/api/rx_broadcast"
            print(url)

            try:
                JSON_object = helper.postJson(payload, headers, url)
                print(JSON_object)
                response = JSON_object.get("response", None)
                if response == "ok":
                    print("broadcast successfully sent")
                else:
                    print("response not OK")
            except:
                print("FAILED TO BROADCAST!")
    
    def sendPrivateMessage(self, message, send_user):
        headers = self.createAuthorisedHeader(True)

        user = database.getUserData(send_user)
        user_address = user.get("address", None)
        user_location = user.get("location", None)
        user_pubkey = user.get("pubkey", None)
        
        encr_message = helper.encryptMessage(message, user_pubkey)
        loginserver_record = database.getUserInfo(self.username, "loginrecord")        
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
        if user_address is None:
            return 1
        url = "http://" + user_address + "/api/rx_privatemessage"
        if send_user == "admin":
            url = "http://cs302.kiwi.land/api/rx_privatemessage"
    
        database.addsentMessages(self.username, send_user, message, ts, "user") #maybe change to encrypted? nah

        try:
            JSON_object = helper.postJson(payload, headers, url)
            response = JSON_object.get("response", None)
            if response == "ok":
                print("pm sent successfully sent")

            else:
                print("response not OK")
        except:
            print("FAILED TO SEND MESAGE")
    
    def createGroupChatP2p(self, target_usernames):
        print("creating group chats")
        #generating symmetric keys to be stored
        key = helper.generateRandomSymmetricKey()
        helper.addToPrivateData(self.logserv, "prikeys", key) #not sure if you can add bytes here....TODO

        #check to see if group exists already
        #TODO

        #create a group invite
        loginserver_record = database.getUserInfo(self.username, "loginrecord")
        groupkey_hash = helper.getShaHash(key)
        groupkey_hash_str = groupkey_hash.decode('utf-8')

        for user in target_usernames:
            username = user
            user = database.getUserData(username)
            user_address = user.get("address", None)
            user_location = user.get("location", None)
            user_pubkey = user.get("pubkey", None)

            encr_groupkey = helper.encryptMessage(key, user_pubkey)
            ts = str(time.time())

            print(loginserver_record)
            print(groupkey_hash_str)
            print(user_pubkey)
            print(encr_groupkey)
            message_bytes = bytes(loginserver_record+groupkey_hash_str+user_pubkey+username+encr_groupkey+ts, encoding='utf-8')
            
            signed = self.signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
            signature_hex_str = signed.signature.decode('utf-8')

            payload = {
                "loginserver_record": loginserver_record,
                "groupkey_hash": groupkey_hash_str,
                "target_pubkey": user_pubkey,
                "target_username": username,
                "encrypted_groupkey": encr_groupkey,
                "sender_created_at": ts,
                "signature": signature_hex_str
            }

            if user_address is None:
                continue
            url = "http://" + user_address + "/api/rx_groupinvite"
            print(url)

            try:
                JSON_object = helper.postJson(payload, headers, url)
                print(JSON_object)
                response = JSON_object.get("response", None)
                if response == "ok":
                    print("group invite sent successfully")
                else:
                    print("response not OK")
            except:
                print("FAILED TO SEND!")
    
    def sendGroupMessage(self, target_group_hash, message):
        headers = self.createAuthorisedHeader(True)
        print(headers)
        print(message)
        key = "6767567jbkjghjbgjhnb"
        
        encr_message = helper.encryptStringKey(key, message)
        loginserver_record = database.getUserInfo(self.username, "loginrecord")        
        ts = str(time.time())
        message_bytes = bytes(loginserver_record+encr_message+ts, encoding='utf-8')
        signed = self.signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')

        payload = {
            "loginserver_record": loginserver_record,
            "groupkey_hash": target_group_hash,
            "group_message": encr_message,
            "sender_created_at": ts,
            "signature": signature_hex_str
        }
        database.addsentMessages(self.username, target_group_hash, message, ts, "group")
        all_users = database.getAllUsers()

        for user in all_users:
            user_address = user.get("address", None)
            user_status = user.get("status", None)
            if user_address is None or user_status != "online":
                continue
            url = "http://" + user_address + "/api/rx_groupmessage"
            print(url)

            try:
                JSON_object = helper.postJson(payload, headers, url)
                print(JSON_object)
                response = JSON_object.get("response", None)
                if response == "ok":
                    print("message sent")
                    print("url")
                else:
                    print("response not OK")
            except:
                print("FAILED TO sent group message!")
                
    def retrieveBroadcasts(self):
        all_broadcasts = database.getAllBroadcasts()
        data = []
        print(all_broadcasts)
        for broadcast in all_broadcasts:
            tup = {}
            message = broadcast.get("message")
            loginserver = broadcast.get("loginserver_record")
            print(message)
            print(loginserver)
            print(type(loginserver))
            tup["message"] = message
            tup["username"] = "username"
            data.append(tup)
        JSON = {"data": data}
        return JSON

        
    '''
    returns an authorised header
    '''
    def createAuthorisedHeader(self, needsAuthentication):

        if needsAuthentication is False:
            headers = {
                'Content-Type' : 'application/json; charset=utf-8'
            }
            return headers

        if self.username is None or self.password is None:
            return None

        #create HTTP BASIC authorization header
        if self.apikey is not None: #change!!! TODO
            headers = {
                'X-username': self.username,
                'X-apikey' : self.apikey,
                'Content-Type' : 'application/json; charset=utf-8',
            }
            
        else: #create api key
            credentials = ('%s:%s' % (self.username, self.password))
            b64_credentials = base64.b64encode(credentials.encode('ascii'))
            headers = {
                'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
                'Content-Type' : 'application/json; charset=utf-8',
            }
        return headers
    
    #need to decrypt it first and THEN 
    def testRecieveMessage(self, message):
        target_username = 'lche982'
        sender_username = 'admin' #after signing etc.
        message = "test Message"
        user = database.getUserData(target_username)
        user_pubkey = user.get("pubkey", None)
        encr_message = helper.encryptMessage(message, user_pubkey)
        loginserver_record = database.getUserInfo(sender_username, "loginrecord")        
        ts = str(time.time())
        database.addReceivedMessage(target_username, user_pubkey, encr_message, ts, message, sender_username) #sending myself a message.
        

            

    
