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

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
j2_env = Environment(loader=FileSystemLoader(THIS_DIR), trim_blocks=True)

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

    @cherrypy.expose
    def index(self):

        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            raise cherrypy.HTTPRedirect('/login')
        else:
            template = j2_env.get_template('web/index.html')
            output = template.render()
        return output
    
    @cherrypy.expose
    def profile(self, name=None):
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
                broadcasts = database.getAllBroadcastsUser(name)
                profile = database.getUserData(name)
                isOwn = False
            print(profile)   
            print(broadcasts) 
            if broadcasts is None:
                broadcasts = [] 
            if profile is None:
                profile = database.getUserData(username)      
                isOwn = True        
            output = template.render(profile=profile, broadcasts=broadcasts, isOwn=isOwn)
        return output
    
    @cherrypy.expose
    def settings(self):

        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            raise cherrypy.HTTPRedirect('/login')
        else:
            template = j2_env.get_template('web/settings.html')
            output = template.render()
        
        return output

    @cherrypy.expose
    def message(self, name=None):

        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            raise cherrypy.HTTPRedirect('/login')
        else:
            template = j2_env.get_template('web/message.html')
            if name is not None:
                messages = database.getConversation("lche982", name)
                if messages is None:
                    messages = []
                output = template.render(username=name,messages=messages)
            else: 
                output = template.render(username=None, messages=[])
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
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        logserv = loginserver.loginserver(username, password)
        error = logserv.getNewApiKey()
        if error > 0:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

        database.checkUsernamePassword(username, password)
        success = logserv.getSigningKey()
        if success > 0:
            print("testing error") #todo: deal with errors
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
        logserv.reportUser("online")
        peer = p2p.p2p(username, password, logserv.signing_key, logserv.apikey)
        cherrypy.session['username'] = username
        cherrypy.session['password'] = password
        cherrypy.session["logserv"] = logserv
        cherrypy.session["p2p"] = peer
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
        if logserv is not None:
            logserv.getUsers()

        for user in users:
            username = user.get("username", None)
            status = user.get("status", None)
            if username is None or status is None:
                continue
            #Page += "<li>" + username + " " + status + "</li>"
            data[username]=status
        #json_return = {"all_users" : Page}
        print("return adata is ")
        print(data)
        return data

    @cherrypy.expose
    def sendBroadcastMessage(self, message=None):
        p2p = cherrypy.session.get("p2p", None)

        if p2p is None or message is None:
            pass
        else:
            p2p.sendBroadcastMessage(message)
        raise cherrypy.HTTPRedirect('/index')
    
    @cherrypy.expose
    def testRecieveMessage(self, message=None):
        p2p = cherrypy.session.get("p2p", None)

        if p2p is None or message is None:
            pass
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
            message = broadcast.get("message")
            username = broadcast.get("username", "user")
            loginserver = broadcast.get("loginserver_record")
            tup["message"] = message
            tup["username"] = username
            data.append(tup)
        JSON = {"data": data}

        return JSON

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def getMessages(self, username=None):
        print("GETTIGN !!!!! MESAGES !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        all_conversations = database.getConversation("lche982", username) #TODO chaange lche982
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
        print("sending private message")
        print(message)
        print(target_user)
        p2p = cherrypy.session.get("p2p", None)
        if p2p is None:
            pass
        else:
            p2p.sendPrivateMessage(message, target_user)
        raise cherrypy.HTTPRedirect('/message?name={a}'.format(a=target_user)) 
    
    @cherrypy.expose
    def reportUser(self, status=None):
        print("reporting user!!!!!!!!!!!")
        print(status)
        if not status:
            status = "online"
        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            pass
        else:
            logserv.reportUser(status)
        
    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            pass
        else:
            logserv.reportUser("offline")
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')



#TODO : create api key (user name , password)