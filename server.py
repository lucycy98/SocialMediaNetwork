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
import database
import p2p
from jinja2 import Environment, FileSystemLoader
import helper
import cherrypy.process.plugins
import threading

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
j2_env = Environment(loader=FileSystemLoader(THIS_DIR), trim_blocks=True, autoescape=True)

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
        cherrypy.response.status = 404
        template = j2_env.get_template('web/404.html')
        output = template.render(url_index='index')
        return output
    
    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def internal_error(self, *args, **kwargs):
        """internal 500 error"""
        cherrypy.response.status = 500
        cherrypy.lib.sessions.expire()
        template = j2_env.get_template('web/500.html')
        output = template.render(url_index='login')
        return output

    @cherrypy.expose
    def index(self, filterVal=None, status=None):
        allusers = database.getAllUsers()

        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            raise cherrypy.HTTPRedirect('/login')
        else:
            username = cherrypy.session["username"]

            if status == 'online':
                logserv.status='online'
            elif status == 'busy':
                logserv.status='busy'
            elif status == 'away':
                logserv.status='away'
            
            if status: 
                logserv.reportUser()

            if filterVal == "favourite":
                all_broadcasts = database.getFavBroadcasts(username)
            elif filterVal == "safe":
                all_broadcasts = database.getAllBroadcasts()
            else:
                all_broadcasts = database.getAllBroadcasts()
                filterVal = "recent"

            if not all_broadcasts:
                all_broadcasts = []
            data = []
            for broadcast in all_broadcasts:
                tup = {}     
                message = broadcast.get("message") 
                broadcastUser = broadcast.get("username")      
                time = broadcast.get("sender_created_at")
                sig = broadcast.get("signature")

                validMessage = helper.checkValidMessage(username, message)
                validUser = helper.checkValidUser(username, broadcastUser)

                if filterVal == "safe": #if block, then block ALL broadcasts by everyone.
                    validBroadcast = helper.checkValidBroadcastAll(sig)
                else:
                    validBroadcast = helper.checkValidBroadcast(username, sig)

                if not validUser or not validBroadcast:
                    tup["username"] = 'invalid username' #dont display at all
                else:
                    tup["username"] = broadcastUser
                
                if not validMessage:
                    tup["message"] = 'invalid message'
                else:
                    tup["message"] = message
                
                tup["time"] = helper.formatTime(time)
                tup["signature"] = sig
                tup["likes"] = database.getNumberLikesBroadcasts(broadcast.get("signature", None))
                data.append(tup)
            template = j2_env.get_template('web/index.html')
            output = template.render(broadcasts=data, filter=filterVal, allusers=allusers)
        return output
    
    @cherrypy.expose
    def profile(self, name=None, filterVal=None):
        allusers = database.getAllUsers()
        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            raise cherrypy.HTTPRedirect('/login')
        else:
            template = j2_env.get_template('web/profile.html')
            username = cherrypy.session.get("username")

            if name == username or name is None:
                broadcasts = database.getAllBroadcastsUser(username)
                profile = database.getUserData(username)
                isOwn = True
            else:
                profile = database.getUserData(name)
                validUser = helper.checkValidUser(username, name)
                if not validUser:
                    profile["username"] = "Blocked user"
                if filterVal == "favourite":
                    broadcasts = database.getFavBroadcasts(name)
                elif filterVal == "blocked":
                    broadcasts = database.getFavBroadcasts(name)
                else:
                    broadcasts = database.getAllBroadcastsUser(name)
                    filterVal = "recent"

                isOwn = False
          
            if not broadcasts:
                broadcasts = []

            for broadcast in broadcasts:
                message = broadcast.get("message") 
                broadcastUser = broadcast.get("username")      
                time = broadcast.get("sender_created_at")
                sig = broadcast.get("signature")

                validMessage = helper.checkValidMessage(username, message)
                validBroadcast = helper.checkValidBroadcast(username, sig)

                if not validBroadcast:
                    broadcast["username"] = 'invalid username' #dont display at all
                
                if not validMessage:
                    broadcast["message"] = 'invalid message'

                time = broadcast.get("sender_created_at")
                broadcast["time"] = helper.formatTime(time)
                broadcast["likes"] = database.getNumberLikesBroadcasts(broadcast.get("signature", None))

            output = template.render(profile=profile, broadcasts=broadcasts, isOwn=isOwn, allusers=allusers)
        return output
    
    @cherrypy.expose
    def settings(self, blockWord=None, unblockWord=None, blockUser=None, unblockUser=None):
        print("called settings")
        allusers = database.getAllUsers()

        logserv = cherrypy.session.get("logserv", None)
        username = cherrypy.session.get("username", None)
        if logserv is None or not username:
            raise cherrypy.HTTPRedirect('/login')
        else:

            if blockWord:
                database.addBlockedWord(username, blockWord)
            elif unblockWord:
                database.deleteBlockedWord(username, unblockWord)
            elif blockUser:
                database.addBlockedUser(username, blockUser)
            elif unblockUser:
                database.deleteBlockedUser(username, unblockUser)

            blockedUsers = database.getBlockedUser(username)
            blockedWords = database.getBlockedWords(username)

            template = j2_env.get_template('web/settings.html')
            output = template.render(blocked_words=blockedWords, blocked_users=blockedUsers, allusers=allusers)
        
        return output

    @cherrypy.expose
    def message(self, name=None, groupname=None):

        logserv = cherrypy.session.get("logserv", None)
        
        if logserv is None:
            raise cherrypy.HTTPRedirect('/login')
        else:
            myUsername = cherrypy.session["username"]
            messages = []
            data = {}
            template = j2_env.get_template('web/message.html')
            users = database.getAllUsers()
            groupchats = database.getAllGroupChats(myUsername)
            online_users = []
            if not users:
                users = []
            
            for user in users:
                username = user.get("username", None)
                status = user.get("status", None)
                validUser = helper.checkValidUser(myUsername, username)
                if not username or not status or not validUser:
                    continue
                data[username]=status
                if status == 'online':
                    online_users.append(username)

            if name is not None or groupname is not None:
                signing_key = logserv.signing_key
                username = cherrypy.session.get("username")
                isGroup = False
                if name is not None:
                    messages = database.getUserConversation(username, name)
                else:
                    groupkeys = database.checkGroupKey(username)
                    for groupkey in groupkeys:
                        encr_groupkey = groupkey.get("groupkey_encr", None)
                        try:
                            decrypted_groupkey = helper.decryptMessage(encr_groupkey, logserv.signing_key)
                            groupkey_str = decrypted_groupkey.hex()
                        except Exception as e:
                            print("ERROR in decrypting group key.")
                            print(e)
                        else:
                            helper.addToPrivateData(logserv, "prikeys", groupkey_str) #not sure if you can add bytes here....TODO
                            database.deleteGroupKey(username, encr_groupkey)

                    messages = database.getGroupConversation(username, groupname)
                    
                    isGroup = True
        
                if messages is None:
                    messages = []
                
                for message in messages:
                    time = message["sender_created_at"]
                    time = helper.formatTime(time)
                    message["time"] = time 
                    

                    encr_message = message["message"]
                    status = message["sent"]
                    decr_message = None

                    if status == "received" and isGroup:

                        validUser = helper.checkValidUser(cherrypy.session["username"], message["username"])
                        if not validUser:
                            message["username"] == 'invalid user'

                        target_group_bytes = bytes(groupname, encoding='utf-8')
                        try: 
                            key = helper.getEncryptionKey(logserv, target_group_bytes)
                        except Exception as e:
                            print(e)
                            key = None


                        #dex hexing message 
                        try: 
                            bytes_message = bytes.fromhex(encr_message)
                            decr_message = helper.decryptStringKey(key, bytes_message)
                        except Exception as e:
                            print(e)
                            decr_message = None
                       
                    else:
                        try: 
                            decr_message = helper.decryptMessage(encr_message, signing_key)
                            decr_message = decr_message.decode('utf-8')    
                        except Exception as e:
                            print(e)
                            print("error decrypting message")
                            decr_message = None           
                    if not decr_message:
                        print("ERROR")
                        decr_message = "ERROR DECRYPTING"

                    validMessage = helper.checkValidMessage(username, decr_message)
                    if not validMessage:
                        decr_message = "invalid message"
                    
                   

                    message["message"] = decr_message
        output = template.render(username=name, messages=messages, onlineusers=data, groupchats=groupchats, groupname=groupname, allusers=users)
        return output
        
        
    @cherrypy.expose
    def login(self, bad_attempt=None):
        #database.getConversation("lche982", "admin")
        template = j2_env.get_template('web/login.html')
        if bad_attempt:
            print("bad attempt!")
            output = template.render(message='You provided an invalid set of username and password. Please try again.')
        else:
            output = template.render()
        return output

    ################################################### INTERNAL API ####################################################

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None, password2=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        logserv = loginserver.loginserver(username, password, password2)
        error = logserv.getNewApiKey()
        if error > 0:
            cherrypy.lib.sessions.expire()
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
        phash = helper.getShaHash(password)
        database.checkUsernamePassword(username, phash)
        success = logserv.getSigningKey()
        if success > 0:
            cherrypy.lib.sessions.expire()
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
        peer = p2p.p2p(username, password, logserv.signing_key, logserv.apikey, logserv)
        cherrypy.session['username'] = username
        cherrypy.session['password'] = password
        cherrypy.session["logserv"] = logserv
        cherrypy.session["p2p"] = peer


        data = database.getUserData(username)
        if not data:
            since = str(time.time() - 1000)
        else:
            since =str(data.get("lastReport"))

        threadReport = loginserver.MyThread(logserv, peer)
        cherrypy.session["thread"] = threadReport
        threadReport.start()

        offline_thread = threading.Thread(target=peer.retrieveOfflineData, args=(since,))
        offline_thread.start()
        raise cherrypy.HTTPRedirect('/index')
    
    @cherrypy.expose
    def checkpubkey(self):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            pass
        else:
            logserv.testPublicKey()
        raise cherrypy.HTTPRedirect('/index')    
          

    # LOGGING IN AND OUT
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def listActiveUsers(self):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        logserv = cherrypy.session.get("logserv", None)
        users = database.getAllUsers()
        Page = ""
        data = {}
        for user in users:
            username = user.get("username", None)
            status = user.get("status", None)
            if username is None or status is None:
                continue
            data[username]=status
        return data

    @cherrypy.expose
    def sendBroadcastMessage(self, message=None):
        p2p = cherrypy.session.get("p2p", None)

        if p2p is None or message is None:
            pass
        else:
            message_thread = threading.Thread(target=p2p.sendBroadcastMessage, args=(message,))
            message_thread.start()
        raise cherrypy.HTTPRedirect('/index')

    
    @cherrypy.expose
    def favouriteBroadcast(self, signature):       
        p2p = cherrypy.session.get("p2p", None)
        logserv = cherrypy.session.get("logserv", None)

        if not p2p or not signature or not logserv:
            #pass
            cherrypy.response.status = 400
        else:
            database.addFavBroadcast(cherrypy.session["username"], signature)
            pd_thread = threading.Thread(target=helper.addToPrivateData, args=(logserv, "favourite_message_signatures", signature))
            pd_thread.start()
            #helper.addToPrivateData(logserv, "favourite_message_signatures", signature)
            message = "!Meta:favourite_broadcast:" + signature
            bc_thread = threading.Thread(target=p2p.sendBroadcastMessage, args=(message,))
            bc_thread.start()
    
    @cherrypy.expose
    def blockBroadcast(self, signature):
        p2p = cherrypy.session.get("p2p", None)
        logserv = cherrypy.session.get("logserv", None)

        if not p2p or not signature or not logserv:
            cherrypy.response.status = 400
        else:
            database.addBlockedBroadcast(cherrypy.session["username"], signature)
            pd_thread = threading.Thread(target=helper.addToPrivateData, args=(logserv, "blocked_message_signatures", signature))
            pd_thread.start()
            #helper.addToPrivateData(logserv, "blocked_message_signatures", signature)
            message = "!Meta:block_broadcast:" + signature
            bc_thread = threading.Thread(target=p2p.sendBroadcastMessage, args=(message,))
            bc_thread.start()

    @cherrypy.expose
    def blockUser(self, username):
        p2p = cherrypy.session.get("p2p", None)
        logserv = cherrypy.session.get("logserv", None)

        if not p2p or not username:
            pass
        else:
            database.addBlockedUser(cherrypy.session["username"], username)
            pd_thread = threading.Thread(target=helper.addToPrivateData, args=(logserv, "blocked_usernames", username))
            pd_thread.start()
            #helper.addToPrivateData(logserv, "blocked_message_signatures", signature)
            message = "!Meta:block_username:" + username
            bc_thread = threading.Thread(target=p2p.sendBroadcastMessage, args=(message,))
            bc_thread.start()
    
    @cherrypy.expose
    def testRecieveMessage(self, message=None):
        p2p = cherrypy.session.get("p2p", None)

        if p2p is None or message is None:
            cherrypy.response.status = 400
        else:
            p2p.testRecieveMessage(message)
        raise cherrypy.HTTPRedirect('/index')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def getBroadcasts(self, username=None):
        all_broadcasts = database.getAllBroadcasts()
        data = []
        for broadcast in all_broadcasts:
            tup = {}            
            tup["message"] = broadcast.get("message")
            tup["username"] = broadcast.get("username")
            time = broadcast.get("sender_created_at")
            tup["time"] = helper.formatTime(time)

            data.append(tup)
        JSON = {"data": data}

        return JSON

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def getMessages(self, username=None):
        my_username = cherrypy.session.get("username")
        all_conversations = database.getUserConversation(my_username, username)
        if all_conversations is None:
            all_conversations = []
        data = {"data":all_conversations}
        return data

    @cherrypy.expose
    def updateLoginServerRecord(self):
        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            pass
        else:
            logserv.getLoginServerRecord()
        raise cherrypy.HTTPRedirect('/index') 

    
    @cherrypy.expose
    def sendPrivateMessage(self, message, target_user):
        p2p = cherrypy.session.get("p2p", None)
        if p2p is None:
            pass
        else:
            print(target_user)
            success = p2p.sendPrivateMessage(message, target_user)
        raise cherrypy.HTTPRedirect('/message?name={a}'.format(a=target_user)) 
    
    @cherrypy.expose
    def sendGroupMessage(self, message, groupname):
        p2p = cherrypy.session.get("p2p", None)
        if p2p is None:
            pass
        else:
            print("group name is ")
            print(groupname)
            p2p.sendGroupMessage(groupname, message)
        raise cherrypy.HTTPRedirect('/message?groupname={a}'.format(a=groupname)) 


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def createGroupChat(self):
        p2p = cherrypy.session.get("p2p", None)
        if p2p is None:
            pass
        else:
            payload = cherrypy.request.json
            print("RECIEVED GROUP CHAT PAYLOAD!!")
            print(payload)
            names = payload["names"]
            if len(names) == 1:
                #create message instead of group chat
                raise cherrypy.HTTPRedirect('/message?name={a}'.format(a=names[0]))
            elif len(names) == 0:
                return

            error, groupkey_hash = p2p.createGroupChatP2p(names)
            print("DONE")
            print(groupkey_hash)
            #if error == 0: #invite sent to at least one person for every req
            raise cherrypy.HTTPRedirect('/message?groupname={a}'.format(a=groupkey_hash)) 
        raise cherrypy.HTTPRedirect('/index')
        
    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        logserv = cherrypy.session.get("logserv", None)
        th = cherrypy.session.get("thread", None)
        if logserv is None or th is None:
            pass
        else:

            th.stop()
            logserv.reportUser("offline")
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')
