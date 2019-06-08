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
import re


class p2p():
    def __init__(self, username, password, signing_key, api, logserv):
        self.logserv = logserv
        self.username = username
        self.password = password
        self.signing_key = signing_key
        self.apikey = api
    
    def pingCheckUsers(self):
        headers = self.createAuthorisedHeader(False)
        ts = str(time.time())

        all_users = database.getAllUsers()

        payload = {
            "my_time": ts,
            "connection_address": self.logserv.connection_address,
            "connection_location": self.logserv.connection_location
        }

        for user in all_users:
            username = user.get("username", None)
            user_address = user.get("address", None)
            user_status = user.get("status", None)
            if user_address is None or user_status != "online":
                continue
            url = "http://" + user_address + "/api/ping_check"
            print(url)

            try:
                JSON_object = helper.postJson(payload, headers, url)
                print(JSON_object)
                response = JSON_object.get("response", None)
                if response == "ok":
                    print("broadcast successfully sent")
                else:
                    print("ping check not ok")
                    database.makeUserOffline(username)
            except:
                print("cannot ping this user!!!!")
                database.makeUserOffline(username)
    



        


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

        isMeta =re.search("^!(M|m)eta:", message)
        if not isMeta:
            database.addBroadCast(loginserver_record, message, ts, signature_hex_str, username, 'false')
        else:
            database.addBroadCast(loginserver_record, message, ts, signature_hex_str, username, 'true')

    
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
        user_pubkey = user.get("pubkey", None)
        user_status = user.get("status", None)
        
        encr_message = helper.encryptMessage(message, user_pubkey)
        loginserver_record = database.getUserInfo(self.username, "loginrecord")        
        ts = str(time.time())
        message_bytes = bytes(loginserver_record+user_pubkey+send_user+encr_message+ts, encoding='utf-8')
        signed = self.signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')

        pubkey_hex = self.signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        try:
            self_encrypted_message = helper.encryptMessage(message, pubkey_hex)
        except Exception as e: 
            print("failed to encrypt sent message.")
            print(e)
        database.addsentMessages(self.username, send_user, self_encrypted_message, ts, "user") #maybe change to encrypted? nah

        
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

        all_users = database.getAllUsers()
        
        if user_status == "online":
            user = database.getUserData(send_user)
            all_users = [user]

        for user in all_users:
            user_address = user.get("address", None)
            user_status = user.get("status", None)
            if user_address is None or user_status != "online":
                continue
            url = "http://" + user_address + "/api/rx_privatemessage"
            if send_user == "admin":
                url = "http://cs302.kiwi.land/api/rx_privatemessage"
            
            try:
                JSON_object = helper.postJson(payload, headers, url)
                response = JSON_object.get("response", None)
                if response == "ok":
                    print("pm sent successfully sent")
                else:
                    print("response not OK")
            except Exception as e:
                print("FAILED TO SEND MESAGE")
                print(e)
    
    def createGroupChatP2p(self, target_usernames):
        headers = self.createAuthorisedHeader(True)
        print("creating group chats")
        error = 1
        #generating symmetric keys to be stored
        key = helper.generateRandomSymmetricKey()
        key_str = key.hex()
        print("original key is")
        print(key)
        helper.addToPrivateData(self.logserv, "prikeys", key_str) #not sure if you can add bytes here....TODO

        #check to see if group exists already
        #TODO

        #create a group invite
        loginserver_record = database.getUserInfo(self.username, "loginrecord")
        groupkey_hash = helper.getShaHash(key)
        print("group key hash is ")
        print(groupkey_hash)
        groupkey_hash_str = groupkey_hash.decode('utf-8')
        database.addGroupChatReceived(groupkey_hash_str, self.username)

        encr = helper.getEncryptionKey(self.logserv, groupkey_hash)
        print("encr is")
        print(encr)
        

        for username in target_usernames:
            database.addGroupChatReceived(groupkey_hash_str, username) #change TODO only add if successful.
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
                    error = 0
                else:
                    print("response not OK")
            except Exception as e:
                print("FAILED TO SEND!")
                print(e)
            error = 0 #TODO CHNAGE THIS IS JUST FOR TETSING
        return error, groupkey_hash_str
    
    def sendGroupMessage(self, target_group_hash, message):
        headers = self.createAuthorisedHeader(True)
        print(headers)
        print(message)
        print("target group hash")
        print(target_group_hash)
        print("")
        target_group_bytes = bytes(target_group_hash, encoding='utf-8')
        key = helper.getEncryptionKey(self.logserv,target_group_bytes)
        
        print("KEY IS")
        if not key:
            print("ERROR!!!!!!!!!!!!!!!1")
            print("ERROR IN SENDING MESSAGE")
            return 1
        
        encr_message = helper.encryptStringKey(key, message).hex() #TODO change if hex is appropriate.
        #encr_message = helper.encryptMessage(message, user_pubkey)
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
        pubkey_hex = self.signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        try:
            self_encrypted_message = helper.encryptMessage(message, pubkey_hex)
        except Exception as e: 
            print("failed to encrypt sent message.")
            print(e)
        print("TRYING TO ADD SEND MESSAGE TO DATABASE.....")
        database.addsentMessages(self.username, target_group_hash, self_encrypted_message, ts, "group")
        print(target_group_hash)
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

    def retrieveOfflineData(self):
        headers = self.createAuthorisedHeader(True)

        since = str(time.time())
        all_users = database.getAllUsers()
        for user in all_users:
            user_address = user.get("address", None)
            user_status = user.get("status", None)
            if user_address is None or user_status != "online":
                continue
            url = "http://" + user_address + "/api/rx_checkmessages?since=" + since
            print(url)

            try:
                JSON_object = helper.postJson(None, headers, url)
                print(JSON_object)
            except:
                print("FAILED TO sent group message!")
                return 1

            response = JSON_object.get("response", None)
            if response == "ok":
                broadcasts = JSON_object.get("broadcasts", None)
                private_messages = JSON_object.get("private_messages", None)
                for broadcast in broadcasts:
                    loginserver_record = broadcast.get("loginserver_record", None)
                    if not loginserver_record:
                        continue
                    message = broadcast.get("message", None)
                    username, pubkey, server_time, signature_str = helper.breakLoginRecord(loginserver_record)
                    isMeta = re.search("^!Meta:(\w+):(\w+)", message)
                    if not isMeta:
                        database.addBroadCast(broadcast.get("loginserver_record", None), broadcast.get("message", None), broadcast.get("sender_created_at", None), broadcast.get("signature", None), username, 'false')
                    else:
                        database.addBroadCast(broadcast.get("loginserver_record", None), broadcast.get("message", None), broadcast.get("sender_created_at", None), broadcast.get("signature", None), username, 'true')
                        key = isMeta.group(1)
                        val = isMeta.group(2)
                        helper.addMetaData(key,val,username)
                
                for pm in private_messages:
                    loginserver_record = broadcast.get("loginserver_record", None)
                    if not loginserver_record:
                        continue
                    username, pubkey, server_time, signature_str = helper.breakLoginRecord(loginserver_record)
                    database.addReceivedMessage(pm.get("target_username", None), pm.get("target_pubkey", None), pm.get("encrypted_message", None), pm.get("sender_created_at", None), pm.get("signature", None), username, loginserver_record, 'false')
            else:
                print("response not OK")


        
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
        loginrecord = user.get("loginserver_record", None)
        encr_message = helper.encryptMessage(message, user_pubkey)
        ts = str(time.time())
        database.addReceivedMessage(target_username, user_pubkey, encr_message, ts, message, sender_username, loginrecord, 'false') #sending myself a message.
        

            

    
