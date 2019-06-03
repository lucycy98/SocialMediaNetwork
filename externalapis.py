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
        payload = cherrypy.request.json

        loginserver_record = payload.get("loginserver_record", None)
        message = payload.get("message", None)
        sender_created_at = payload.get("sender_created_at", None)
        signature = payload.get("signature", None)

        if not loginserver_record or not message or not signature:
            error = "missing parameters in request"
        else:   
            username, pubkey, server_time, signature_str = helper.breakLoginRecord(loginserver_record)
            message = str(loginserver_record)+str(message)+str(sender_created_at)
            try: 
                helper.verifyMessageSignature(message, pubkey, signature)
            except nacl.exceptions.BadSignatureError as e:
                error = "bad signature error."
                print(e)
            else:
                database.addBroadCast(loginserver_record, message, sender_created_at, signature, username)
        response = helper.generateResponseJSON(error)
        return response
    
    #recieving messages from thers. 
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ping_check(self):
        response = {}
        username = cherrypy.session.get("username")
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
    def HI(self):
        error = "ok"
        print("recieving prvate message!")
        payload = cherrypy.request.json

        loginserver_record = payload.get("loginserver_record", None)
        target_pubkey = payload.get("target_pubkey", None)
        encr_message = payload.get("encrypted_message", None)
        sender_created_at = payload.get("sender_created_at", None)
        signature = payload.get("signature", None)
        target_username = payload.get("target_username", None)

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
                database.addBroadCast(loginserver_record, message, sender_created_at, signature, username)
        response = helper.generateResponseJSON(error)
        return response