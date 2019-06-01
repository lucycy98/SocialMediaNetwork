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
    def profile(self):

        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            raise cherrypy.HTTPRedirect('/login')
        else:
            template = j2_env.get_template('web/profile.html')
            output = template.render()
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
    def message(self):

        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            raise cherrypy.HTTPRedirect('/login')
        else:
            template = j2_env.get_template('web/message.html')
            output = template.render()
        return output
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        if bad_attempt != 0:
            print("bad attempt!")
            
        Page = open("web/login.html").read()
        return Page
        
      
    ################################################### INTERNAL API ####################################################

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        logserv = loginserver.loginserver(username, password)
        error = database.checkUsernamePassword(username, password)

        if error == 0:
            success = logserv.getSigningKey()
            if success > 0:
                print("testing error") #todo: deal with errors
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
            logserv.reportUser("online")
            peer = p2p.p2p(username, password, logserv.signing_key)
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            cherrypy.session["logserv"] = logserv
            cherrypy.session["p2p"] = peer
            raise cherrypy.HTTPRedirect('/index')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
    
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
        if logserv is not None:
            logserv.getUsers()

        for user in users:
            username = user.get("username", None)
            if username is not None:
                Page += username + "</br>"
        
        json_return = {"all_users" : Page}
        print("return adata is ")
        print(json_return)
        return json_return

    @cherrypy.expose
    def updateLoginServerRecord(self):
        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            pass
        else:
            logserv.getLoginServerRecord()
        raise cherrypy.HTTPRedirect('/index') 

    @cherrypy.expose
    def sendBroadcastMessage(self):
        p2p = cherrypy.session.get("p2p", None)

        if p2p is None:
            pass
        else:
            p2p.sendBroadcastMessage("HELLO!!!")
        raise cherrypy.HTTPRedirect('/index') 
    
    @cherrypy.expose
    def sendPrivateMessage(self):
        p2p = cherrypy.session.get("p2p", None)

        if p2p is None:
            pass
        else:
            p2p.sendPrivateMessage("ADMIN MESSG", "admin")
        raise cherrypy.HTTPRedirect('/index') 
        

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