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

'''
This class deals with sending other users in the network requests
e.g ping checks, broadcasts, private/group chat messaging, offline retrieval etc
''' 


class p2p():
    def __init__(self, username, password, signing_key, api, logserv):
        self.logserv = logserv
        self.username = username
        self.password = password
        self.signing_key = signing_key
        self.apikey = api
    
    '''
    sends all users that are "online" a ping check
    if fails, then marks them as offline
    ''' 
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
            try:
                JSON_object = helper.postJson(payload, headers, url)
                response = JSON_object.get("response", None)
                if response == "ok":
                    print("ping check successful")
                else:
                    print("ping check not ok")
                    database.makeUserOffline(username)
            except:
                print("cannot ping this user!!!!")
                database.makeUserOffline(username)

    '''
    sends a broadcast message to all users in the network
    checks if message is meta message and stores in database accordingly

    ''' 
    def sendBroadcastMessage(self, message):
        headers = self.createAuthorisedHeader(False)
  
        ud = database.getUserHashes(self.username)
        loginserver_record = ud.get("loginrecord")
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
        try: 
            username, pubkey, server_time, signature_str = helper.breakLoginRecord(loginserver_record)
        except Exception as e:
            print(e)
            return 1

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

            try:
                JSON_object = helper.postJson(payload, headers, url)
                print(JSON_object)
                response = JSON_object.get("response", None)
                if response == "ok":
                    print("broadcast successfully sent")
                else:
                    print("response not OK")
            except:
                print("FAILED TO BROADCAST to url " + str(url))
    '''
    deals with sending private messages
    gets the end users public key for encryption of message
    stores into db
    encrypts own message with own public key for storage into db
    checks if user is online, or response was successful
    if not, then send to other users in network as offline messge.
    ''' 
    def sendPrivateMessage(self, message, send_user):
        headers = self.createAuthorisedHeader(False)

        user = database.getUserData(send_user)
        user_address = user.get("address", None)
        user_pubkey = user.get("pubkey", None)
        user_status = user.get("status", None)
        try: 
            encr_message = helper.encryptMessage(message, user_pubkey)
        except Exception as e:
            print(e)
            print("failed to encrypt message")
            return 1
        ud = database.getUserHashes(self.username)
        loginserver_record = ud.get("loginrecord")        
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
            return 1
        msg = database.addsentMessages(self.username, send_user, self_encrypted_message, ts, "user")
        if msg["response"] == "error":
            return 1
        
        payload = {
            "loginserver_record": loginserver_record,
            "target_pubkey": user_pubkey,
            "encrypted_message": encr_message,
            "target_username": send_user,
            "sender_created_at": ts,
            "signature": signature_hex_str
        }
        
        if user_status == "online":
            user = database.getUserData(send_user)
            user_address = user.get("address", None)
            user_status = user.get("status", None)
            url = "http://" + user_address + "/api/rx_privatemessage"
            
            try:
                JSON_object = helper.postJson(payload, headers, url)
                response = JSON_object.get("response", None)
                if response == "ok":
                    print("pm sent successfully")
                    return 0
                else:
                    raise Exception("error sending private message")
            except Exception as e:
                print("FAILED TO SEND MESAGE")
                print(e)

                all_users = database.getAllUsers()
                #sending offline message.
                for user in all_users:
                    user_address = user.get("address", None)
                    user_status = user.get("status", None)
                    if user_address is None or user_status != "online":
                        continue
                    url = "http://" + user_address + "/api/rx_privatemessage"                    
                    try:
                        JSON_object = helper.postJson(payload, headers, url)
                        response = JSON_object.get("response", None)
                        if response == "ok":
                            print("pm sent successfully sent")
                        else:
                            raise Exception("error sending private message")
                    except Exception as e:
                        print(e)
    '''
    method for creating group chats
    generates a random symmetric key and adds to private data
    gets shahash of key for group identifier
    sends group invite to all members of the group
    ''' 
    def createGroupChatP2p(self, target_usernames):
        headers = self.createAuthorisedHeader(False)
        print("creating group chats")
        error = 0
        #generating symmetric keys to be stored
        key = helper.generateRandomSymmetricKey()
        key_str = key.hex()
        try: 
            helper.addToPrivateData(self.logserv, "prikeys", key_str)
        except Exception as e:
            print(e)
            return 1

        #create a group invite
        ud = database.getUserHashes(self.username)
        loginserver_record = ud.get("loginrecord")
        try: 
            groupkey_hash = helper.getShaHash(key)
        except Exception as e:
            print(e)
            return 1

        groupkey_hash_str = groupkey_hash.decode('utf-8')
        database.addGroupChatReceived(groupkey_hash_str, self.username)

        #encr = helper.getEncryptionKey(self.logserv, groupkey_hash)

        for username in target_usernames:
            
            user = database.getUserData(username)
            user_address = user.get("address", None)
            user_location = user.get("location", None)
            user_pubkey = user.get("pubkey", None)
            try: 
                encr_groupkey = helper.encryptMessage(key, user_pubkey)
            except Exception as e:
                print(e)
                return 1
            ts = str(time.time())

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
                    database.addGroupChatReceived(groupkey_hash_str, username)
                else:
                    print("response not OK")
            except Exception as e:
                print("FAILED TO SEND!")
                print(e)
                error = 1
        return error, groupkey_hash_str

    '''
    sends group message for group identified by hash
    gets encryption key from private data, from comparing sha hash results
    encrypts message using key
    composes message and sends + adds to database
    ''' 
    def sendGroupMessage(self, target_group_hash, message):
        headers = self.createAuthorisedHeader(False)
        target_group_bytes = bytes(target_group_hash, encoding='utf-8')
        try:
            key = helper.getEncryptionKey(self.logserv,target_group_bytes)
        except Exception as e:
            print(e)
            return 1
        
        if not key:
            print("ERROR IN SENDING MESSAGE")
            return 1
        
        try: 
            encr_message = helper.encryptStringKey(key, message).hex() #TODO change if hex is appropriate.
        except Exception as e:
            print(e)
            return 1
            
        #encr_message = helper.encryptMessage(message, user_pubkey)
        ud = database.getUserHashes(self.username)
        loginserver_record = ud.get("loginrecord")       
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
            return 1
        
        print(target_group_hash)

        target_users = database.getGroupUsers(target_group_hash)
        database.addsentMessages(self.username, target_group_hash, self_encrypted_message, ts, "group")

        for tg in target_users:
            username = tg.get("username")
            user = database.getUserData(username)
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

    '''
    offline data is retrieved from all users in network
    adds to database accordingly
    ''' 
    def retrieveOfflineData(self, since):
        headers = self.createAuthorisedHeader(False)

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
            except Exception as e:
                print("cannot retrieveOfflineData from " + str(url))
                print(e)
            else:
                response = JSON_object.get("response", None)
                if response == "ok":
                    broadcasts = JSON_object.get("broadcasts", [])
                    private_messages = JSON_object.get("private_messages", [])
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
            

    
