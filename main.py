#!/usr/bin/python3
""" main.py

    COMPSYS302 - Software Design - Example Client Webapp
    Current Author/Maintainer: Hammond Pearce (hammond.pearce@auckland.ac.nz)
    Last Edited: March 2019

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 18.0.1  (www.cherrypy.org)
#            Python  (We use 3.5.x +)

import os
import cherrypy
import server
import externalapis

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 11318


def runMainApp():
    #set up the config
    conf = {
        '/': {
            'tools.staticdir.root': os.getcwd(),
            'tools.encode.on': True,
            'tools.encode.encoding': 'utf-8',
            'tools.sessions.on': True,
            'tools.sessions.timeout': 60 * 1,  # timeout is in minutes, * 60 to get hours
        },

        #configuration for the static assets directory
        '/images': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.getcwd(), 'web/images')
        },
        '/js': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.getcwd(), 'web/js')
        },
        '/css': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.getcwd(), 'web/css')
        },
        '/img': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.getcwd(), 'web/img')
        }
    }

    cherrypy.site = {
        'base_path': os.getcwd()
    }

    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(server.MainApp(), "/", conf)
    cherrypy.tree.mount(externalapis.MainApp(), "/api/", conf)

    # Tell cherrypy where to listen, and to turn autoreload on
    cherrypy.config.update({'server.socket_host': LISTEN_IP,
                            'server.socket_port': LISTEN_PORT,
                            'engine.autoreload.on': True,
                            })
    #cherrypy.tools.auth = cherrypy.Tool('before_handler', auth.check_auth, 99)

    # Start the web serve
    cherrypy.engine.start()


    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()


#Run the function to start everything
if __name__ == '__main__':
    runMainApp()

