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

'''
1. A user will enter a username and password into a client webapp
2. The client webapp will authenticate the username/password against the login server
(e.g. using /api/ping)
3. The client webapp will ensure that they have a public/private keypair
a. it may choose to create a new keypair and publish to /api/add_pubkey
b. It may choose to load existing keypair(s) (if any are available) from
/api/get_privatedata
4. The client webapp should test the public/private keypair against the login server
a. Using /api/ping
5. The client webapp should report the user is now available online and the connection
info for the user
a. Using /api/report
b. You are not considered “signed in to the network” until you have called
/api/report
6. The client webapp should now report to the user that they are online
'''
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
        username = cherrypy.session.get("username", None)
        if username is None:
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
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(username, password)

        if error == 0:
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            getSigningKey()
            test_success = testPublicKey()
            reportUser()
            if test_success > 0:
                print("testing error") #todo: deal with errors
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
            raise cherrypy.HTTPRedirect('/index')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
    
    # LOGGING IN AND OUT
    @cherrypy.expose
    def checkpubkey(self):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        testPublicKey()
        raise cherrypy.HTTPRedirect('/index')        

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username',None)
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


###
### Functions only after here
###

def reportUser():
    headers = createAuthorisedHeader()
    url = "http://cs302.kiwi.land/api/report"
    signing_key = cherrypy.session.get("signing_key")
    pubkey = signing_key.verify_key
    pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')
    connection_address = "127.0.0.1:8000"
    connection_location = "2"

    payload = {
        "connection_address" :connection_address,
	    "connection_location" : connection_location,
        "incoming_pubkey": pubkey_hex_str
    }

    JSON_object = postJson(payload, headers, url)
    print(JSON_object)
    response = JSON_object.get("response", None)
    if response == "ok":
        print("reported successfully.")
        return 0
    else:
        print ("error in reporting")
        return 1
    
    

'''
tests whether the user has provided a valid public key associated 
with the account. if there is an error
'''
def testPublicKey():
    url = "http://cs302.kiwi.land/api/ping"
    signing_key = cherrypy.session.get("signing_key", None)

    if signing_key is None:
        return 1
    
    pubkey = signing_key.verify_key
    pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

        #creating message and then signed
    message_bytes = bytes(pubkey_hex_str, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
    print(signature_hex_str)

    headers = createAuthorisedHeader()
    payload = {
        "pubkey" : pubkey_hex_str,
        "signature": signature_hex_str
    }
    
    JSON_object = postJson(payload, headers, url)
    print(JSON_object)
    response = JSON_object.get("response", None)
    signature = JSON_object.get("signature", None)
    if response == "ok" and signature == "ok":
        print("public key and signature is valid.")
        return 0
    else:
        print ("public key and or signature is invalid.")
        return 1

'''
goes through the private data on the account, and checks if a signing key has already
been created on the account. if yes, add that to the session. if not, create a new 
signing key and update the private data.
'''
def getSigningKey():
    private_data = getPrivateData()
    hex_key = private_data.get("prikeys", None)
    error = 0
    if hex_key is None:
        #create a public key and add to private data
        addPublicKey()
        error = testPublicKey()
        addKeyPrivateData(private_data)
        print("HEX KEY IS NONE")
    else:
        cherrypy.session["hex_key"] = hex_key
        signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
        cherrypy.session["signing_key"] = signing_key
        error = testPublicKey()
    
    if error > 0:
        print("an error occured in getting a public key from either the private data or created.")
    return error   
    
'''
adds the public key to the central server to associate that public key. 
'''    
def addPublicKey():
    username = cherrypy.session.get("username", None)   
    url = "http://cs302.kiwi.land/api/add_pubkey"

    # Generate a new random signing key
    hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

    # dealing with public keys
    pubkey = signing_key.verify_key
    pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    #creating message and then signed
    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    print("authorise signature here is")
    print(signature_hex_str)

    headers = createAuthorisedHeader()
    payload = {
        "pubkey" : pubkey_hex_str,
        "username" : username,
        "signature" : signature_hex_str
    }
    
    JSON_object = postJson(payload, headers, url)
    print(JSON_object)
    response = JSON_object.get("response", None)
    login_server_record = JSON_object.get("loginserver_record", None)

    if response == "ok" and login_server_record is not None:
        print("pubkey added successfully!")
        cherrypy.session['signing_key'] = signing_key
        cherrypy.session['hex_key'] = hex_key
        cherrypy.session['login_server_record'] = login_server_record
        return 0
    else:
        print ("Failed to add pubkey")
        return 1

'''produces the symmetric key'''
def getSecretKey():
    if not os.path.isfile("secret.bin"): #if key has not been generated before
        key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        print(type(key))
        with open("secret.bin", "wb") as f:
            f.write(key)
        return key
    else:
        with open('secret.bin', "rb") as f:
            hexed_key = f.read()
        return hexed_key       

'''
takes in a string as input, and encrypts it with the SecretBox
'''
def encryptString(input):
    input_bytes = bytes(input, encoding='utf-8') 
    key = getSecretKey()
    print("key")
    print(key)
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(input_bytes, nonce)
    print("encrypted is ")
    print(encrypted)
    print(type(encrypted))
    return encrypted

'''
takes in an encrypted messge, and returns a decryped version (string)
'''
#TODO: error message when the key cannot decrypt the message.
def decryptString(input):
    key = getSecretKey()
    print("key")
    print(key)
    box = nacl.secret.SecretBox(key)
    print("trying to decrypt the message plaintext:")
    plaintext = box.decrypt(input) #should be bytes
    print(plaintext)
    data = plaintext.decode("utf-8") 
    print(data)
    return data

'''
returns the private data from get_privatedata in a JSON format
doesnt need to be decrypted.
'''
def getPrivateData():
    url_get = "http://cs302.kiwi.land/api/get_privatedata"
    headers = createAuthorisedHeader()

    JSON_object = postJson(None, headers, url_get)
    response = JSON_object.get("response", None)
    print(JSON_object)
    private_data = {}
    if response == "ok":
        print("private data is ")
        print(response)
        private_data_encr = JSON_object.get("privatedata")
        print(type(private_data_encr))
        private_data_bytes = bytes.fromhex(private_data_encr)
        print(type(private_data_bytes))
        private_data_str = decryptString(private_data_bytes)
        private_data = json.loads(private_data_str)
    return private_data

'''
adds the public key to the private data
where private data input is the existing private data
returns '0' if added successfully, otherwise error. 
'''
def addKeyPrivateData(private_data):
    url_add = "http://cs302.kiwi.land/api/add_privatedata"
        
    headers = createAuthorisedHeader()
    
    hex_key = cherrypy.session.get("hex_key", None)
    signing_key = cherrypy.session.get("signing_key", None)
    print("HEX KEY IS ")
    print(hex_key)
    print(type(hex_key))
    login_server_record = cherrypy.session.get("login_server_record", None)
    ts = str(time.time())

    private_data["prikeys"] = hex_key.decode('utf-8')
    private_data_str = json.dumps(private_data)
    private_data_encr = encryptString(private_data_str) #encrypted private data
    private_data_hex_str = private_data_encr.hex() #hexed private data

    #creating message and then signed
    message_bytes = bytes(private_data_hex_str + login_server_record + ts, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    payload = {
        "privatedata": private_data_hex_str,
        "loginserver_record": login_server_record,
        "client_saved_at": ts,
        "signature": signature_hex_str
    }

    JSON_object = postJson(payload, headers, url_add)
    print(JSON_object)
    response = JSON_object.get("response", None)
    if response == "ok":
        print("added to private data successfully!")
        return 0
    else:
        print ("Failed to save private data")
        return 1

'''
returns an authorised header
'''
def createAuthorisedHeader():

    username = cherrypy.session.get("username", None)   
    password = cherrypy.session.get("password", None)

    if username is None or password is None:
        return None
    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }
    return headers

'''
sends a POST/GET request to the URL endpoint specified.
returns the JSON response
''' 
def postJson(payload, headers, url):

    if payload is not None:
        payload = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
        return None #unneeded?
    
    JSON_object = json.loads(data.decode(encoding))
    return JSON_object

'''
checks whether the user name and password is valid
'''
def authoriseUserLogin(username, password):
    print("Log on attempt from {0}:{1}".format(username, password))
    if (username.lower() == "lche982") and (password.lower() == "lucycy98_864045152"):
        print("Success")
        return 0
    else:
        print("Failure")
        return 1


if __name__ == '__main__':
    cherrypy.quickstart(MainApp())
    #encryptString("hello")