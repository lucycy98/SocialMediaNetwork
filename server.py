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

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            raise cherrypy.HTTPRedirect('/login')
        else:
            Page = open("static/index.html")

        return Page
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        if bad_attempt != 0:
            print("bad attempt!")
            
        Page = open("static/login.html")
        return Page
        
      
    ################################################### INTERNAL API ####################################################

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        logserv = loginserver.loginserver(username, password)
        db = database.databases(username, password)
        error = db.checkUsernamePassword()

        if error == 0:
            success = logserv.getSigningKey()
            if success > 0:
                print("testing error") #todo: deal with errors
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
            logserv.reportUser("online")
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            cherrypy.session["logserv"] = logserv
            cherrypy.session["database"] = db
            logserv.addDatabase(db)
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
    def listActiveUsers(self):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            pass
        else:
            logserv.getUsers()
        raise cherrypy.HTTPRedirect('/index') 

    @cherrypy.expose
    def updateLoginServerRecord(self):
        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            pass
        else:
            logserv.getLoginServerRecord()
        raise cherrypy.HTTPRedirect('/index') 

    @cherrypy.expose
    def sendMessage(self):
        logserv = cherrypy.session.get("logserv", None)
        if logserv is None:
            pass
        else:
            logserv.getLoginServerRecord()
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