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
import loginserver
import helper
import database
import re

class MainApp(object):

    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        #Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        Page = open("static/error.html")
        return Page

    #recieving messages from thers. 
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_broadcast(self):
        error = "ok"
        print("recieving broadcast message!")
        print(cherrypy.request)
        payload = cherrypy.request.json

        loginserver_record = payload.get("loginserver_record", None)
        message = payload.get("message", None)
        sender_created_at = payload.get("sender_created_at", None)
        signature = payload.get("signature", None)

        if not loginserver_record or not message or not signature:
            error = "missing parameters in request"
        else:   
            username, pubkey, server_time, signature_str = helper.breakLoginRecord(loginserver_record)
            message_signature = str(loginserver_record)+str(message)+str(sender_created_at)
            try: 
                helper.verifyMessageSignature(message_signature, pubkey, signature)
            except nacl.exceptions.BadSignatureError as e:
                error = "bad signature error."
                print(e)
            else:

                isMeta = re.search("^!Meta:(\w+):(\w+)", message)
                if not isMeta:
                    database.addBroadCast(loginserver_record, message, sender_created_at, signature, username, 'false')
                else:
                    database.addBroadCast(loginserver_record, message, sender_created_at, signature, username, 'true')                    
                    key = isMeta.group(1)
                    val = isMeta.group(2)
                    helper.addMetaData(key,val,username)
                    
        response = helper.generateResponseJSON(error)
        return response
    
    #recieving messages from thers. 
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ping_check(self):
        response = {}
        error = "ok"
        print("recieving broadcast message!")
        payload = cherrypy.request.json

        their_time = payload.get("my_time", None)
        their_active_usernames = payload.get("my_active_usernames", None)
        their_address = payload.get("connection_address", None)
        their_location = payload.get("connection_location", None)

        if not their_time or not their_address or not their_location:
            error = "missing parameters in request"
            response["response"] = "error"
            response["message"] = error
        else:   
            response["my_time"] = str(time.time())
            active_users = database.getAllUsersStatus("online")
            if not active_users:
                active_users = []
            users = []
            for user in active_users:
                users.append(user.get("username"))
            response["my_active_users"] = users
        return response

    #recieving private messages
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_privatemessage(self):
        error = "ok"
        print("recieving prvate message!")
        payload = cherrypy.request.json

        loginserver_record = payload.get("loginserver_record", None)
        target_pubkey = payload.get("target_pubkey", None)
        encr_message = payload.get("encrypted_message", None)
        sender_created_at = payload.get("sender_created_at", None)
        signature = payload.get("signature", None)
        target_username = payload.get("target_username", None)
        username, pubkey, server_time, signature_str = helper.breakLoginRecord(loginserver_record)

        if not loginserver_record or not encr_message or not signature or not target_pubkey or not target_pubkey or not sender_created_at:
            error = "missing parameters in request"
        else:   
            username, pubkey, server_time, signature_str = helper.breakLoginRecord(loginserver_record)
            message = str(loginserver_record)+str(target_pubkey)+str(target_username)+str(encr_message)+str(sender_created_at)
            try: 
                helper.verifyMessageSignature(message, pubkey, signature)
            except nacl.exceptions.BadSignatureError as e:
                error = "bad signature error."
                print(e)
            else:
                database.addReceivedMessage(target_username, target_pubkey, encr_message, sender_created_at, encr_message, username, loginserver_record, "false")
        response = helper.generateResponseJSON(error)
        return response
    
    #recieving groupinvites
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_groupinvite(self):
        error = "ok"
        print("recieving group invite!")
        payload = cherrypy.request.json

        loginserver_record = payload.get("loginserver_record", None)
        target_pubkey = payload.get("target_pubkey", None)
        groupkey_hash = payload.get("groupkey_hash", None)
        encr_groupkey = payload.get("encrypted_groupkey", None)
        sender_created_at = payload.get("sender_created_at", None)
        signature = payload.get("signature", None)
        target_username = payload.get("target_username", None)
        print("TARGET USERNAME IS")
        print(target_username)

        if not loginserver_record or not target_pubkey or not groupkey_hash or not encr_groupkey or not signature or not sender_created_at:
            error = "missing parameters in request"
        else:
            username, pubkey, server_time, signature_str = helper.breakLoginRecord(loginserver_record)
            message = str(loginserver_record)+str(groupkey_hash)+str(target_pubkey)+str(target_username)+str(encr_groupkey)+str(sender_created_at)
            try: 
                helper.verifyMessageSignature(message, pubkey, signature)
            except nacl.exceptions.BadSignatureError as e:
                error = "bad signature error."
                print(e)
            else:
                database.addGroupKey(target_username, encr_groupkey) #adding the group key.
                database.addGroupChatReceived(groupkey_hash, target_username)

                '''
                username = cherrypy.session.get("username", None)
                if target_username == username:
                    logserv = cherrypy.session.get("logserv", None)
                    print(logserv)
                    try:
                        decrypted_groupkey = helper.decryptMessage(encr_groupkey, logserv.signing_key)
                        print(decrypted_groupkey)
                        print("decrypted group key is")
                        groupkey_str = decrypted_groupkey.hex()
                        #decrypted_groupkey = helper.decryptStringKey(target_pubkey, encr_groupkey)
                    except Exception as e:
                        print(e)
                    else:
                        helper.addToPrivateData(logserv, "prikeys", groupkey_str) #not sure if you can add bytes here....TODO
                #TODO update keys. 
                '''
        response = helper.generateResponseJSON(error)
        return response

    #recieving private messages
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_groupmessage(self):
        error = "ok"
        print("recieving group message!")
        payload = cherrypy.request.json

        loginserver_record = payload.get("loginserver_record", None)
        groupkey_hash = payload.get("groupkey_hash", None)
        group_message = payload.get("group_message", None)
        sender_created_at = payload.get("sender_created_at", None)
        signature = payload.get("signature", None)

        if not loginserver_record  or not groupkey_hash or not group_message or not signature or not sender_created_at:
            error = "missing parameters in request"
        else:
            username, pubkey, server_time, signature_str = helper.breakLoginRecord(loginserver_record)
            message = str(loginserver_record)+str(group_message)+str(sender_created_at)
            try: 
                helper.verifyMessageSignature(message, pubkey, signature)
            except nacl.exceptions.BadSignatureError as e:
                error = "bad signature error."
                print(e)
            else:
                print("group message is")
                print(group_message)
                database.addGroupMessage(groupkey_hash, username, group_message, sender_created_at, 'false')
        response = helper.generateResponseJSON(error)
        return response
    
    #recieving private messages
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def rx_checkmessages(self, since=None):
        print("recieving check messages!")
        if not since: 
            since = 0
        broadcasts = database.getAllBroadcasts(since=int(since), checkMessages=True)
        pms = database.getAllMessages(since=int(since), checkMessages=None)

        payload = {
            "response": "ok",
            "broadcasts": broadcasts,
            "private_messages": pms
        }
        return payload