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
import os
import helper
import socket

class loginserver():
    def __init__(self, username, password, password2):
        self.username = username
        self.password = password
        self.signing_key = None
        self.connection_address = "47.72.146.59:8080"
        self.connection_location = "2"
        self.users = None
        self.apikey = None
        self.login_server_record = None
        self.getConnectionAddress()
        self.hex_key = None
        self.password2 = password2
        #self.getNewApiKey()

    def ping(self):
        headers = self.createAuthorisedHeader(True)
        url = "http://cs302.kiwi.land/api/ping"
        JSON_object = helper.postJson(None, headers, url)

        response = JSON_object.get("response", None)
        if response == "ok":
            print("valid user name and password")
            return 0
        else:
            message = JSON_object.get("message", None)
            return message
            
    def getConnectionAddress(self):
        ip = urllib.request.urlopen('http://ipv4.icanhazip.com').read()
        publicip = ip.rstrip().decode('utf-8')

        #localip = socket.gethostbyname(socket.gethostname())
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        localip = s.getsockname()[0]

        if '130.216' in publicip:
            self.connection_address = localip
            self.connection_location = '0'
        elif '172.23' in localip or '172.24' in localip:
            self.connection_address = localip
            self.connection_location = '1'
            
        else:
            self.connection_address = publicip
            self.connection_location = '2'
    
        print("MY IP IS")
        print(self.connection_address)
        print(self.connection_location)
    
    '''
    function to report the User. status can be offline, online, away, busy.
    '''
    def reportUser(self, status):
        headers = self.createAuthorisedHeader(True)
        url = "http://cs302.kiwi.land/api/report"
        pubkey = self.signing_key.verify_key
        pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = pubkey_hex.decode('utf-8')
        connection_address = self.connection_address
        connection_location = self.connection_location

        payload = {
            "connection_address" :connection_address,
            "connection_location" : connection_location,
            "incoming_pubkey": pubkey_hex_str,
            "status": str(status)
        }

        JSON_object = helper.postJson(payload, headers, url)

        response = JSON_object.get("response", None)
        if response == "ok":
            return 0
        else:
            print ("error in reporting")
            return 1

    '''
    goes through the private data on the account, and checks if a signing key has already
    been created on the account. if yes, add that to the session. if not, create a new 
    signing key and update the private data.
    '''
    def getSigningKey(self):
        error = 0
        private_data = {}
        private_data = self.getPrivateData()
        print("private data is")
        print(private_data)            
        prikeys = private_data.get("prikeys", None)
        
        if prikeys is None:
            print("HEX KEY IS NONE")
            self.addPublicKey()
            error = self.testPublicKey()
            if error != 0:
               return error
             #creating private data. 
            private_data["prikeys"] = []
            private_data["prikeys"].append(self.hex_key.decode('utf-8'))
            print("private data is")
            print(private_data)
            self.addPrivateData(private_data)
        else:
            hex_key = prikeys[0]
            self.signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
            self.hex_key = hex_key
            error = self.testPublicKey()
        self.getLoginServerRecord()
        print("login server is")
        print(self.login_server_record)
        if error > 0:
            print("an error occured in getting a public key from either the private data or created.")
        return error 

    '''
    gets the ACTIVE users who have done a report in the last 5 minutes to the login server. 
    #TODO : store in database
    '''
    def getUsers(self):
        headers = self.createAuthorisedHeader(True)
        url = "http://cs302.kiwi.land/api/list_users"
        JSON_object = helper.postJson(None, headers, url)

        response = JSON_object.get("response", None)
        if response == 'ok':
            self.users = JSON_object.get("users", None)
            if self.users is not None:
                self.loadUsersIntoDatabase(self.users)
          
          
            return 0   
        else:
            return 1
    

    def loadUsersIntoDatabase(self, reported_users):
        online_users = []
        for user in reported_users:
            username = user.get("username", None)
            status = user.get("status", None)
            online_users.append(user.get("username"))

            if not status:
                    status = "online"
            database.updateUsersInfo(username, user.get("connection_address", None), user.get("connection_location", None), user.get("incoming_pubkey", None), user.get("connection_updated_at", None), status)

        all_users = database.getAllUsers()

        for user in all_users:
            username = user.get("username", None)
            if username is None: 
                "USER IS NONE!!!!!!!!!!!!!!"
                continue
            if username not in online_users:
                database.makeUserOffline(username)    
        #database.printDatabase()


    '''
    gets the ACTIVE users who have done a report in the last 5 minutes to the login server. 
    #TODO : update database
    '''
    def checkPublicKey(self, pubkey_str):
        headers = self.createAuthorisedHeader(True)
        url = "http://cs302.kiwi.land/api/list_users"
        req = "?pubkey=" + pubkey_str
        JSON_object = helper.postJson(None, headers, url+req)

        response = JSON_object.get("response", None)
        if response == 'ok':
            self.users = JSON_object.get("users", None)
            return 0   
        else:
            return 1

    '''
    tests whether the user has provided a valid public key associated 
    with the account. if there is an error
    '''
    def testPublicKey(self):
        url = "http://cs302.kiwi.land/api/ping"

        if self.signing_key is None:
            return 1
        
        pubkey = self.signing_key.verify_key
        pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = pubkey_hex.decode('utf-8')

        #creating message and then signed
        message_bytes = bytes(pubkey_hex_str, encoding='utf-8')
        signed = self.signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')


        headers = self.createAuthorisedHeader(True)
        payload = {
            "pubkey" : pubkey_hex_str,
            "signature": signature_hex_str
        }
        
        JSON_object = helper.postJson(payload, headers, url)

        response = JSON_object.get("response", None)
        signature = JSON_object.get("signature", None)
        if response == "ok" and signature == "ok":
            print("public key and signature is valid.")
            return 0
        else:
            print ("public key and or signature is invalid.")
            return 1

    '''
    saves current loginserver record as a field of the class
    '''
    def getLoginServerRecord(self):
        url = "http://cs302.kiwi.land/api/get_loginserver_record"
        headers = self.createAuthorisedHeader(True)
        JSON_object = helper.postJson(None, headers, url)
        response = JSON_object.get("response", None)
        if response == "ok":
            self.login_server_record = JSON_object.get("loginserver_record", None)
            database.addLoginServerRecord(self.username, self.login_server_record)
            return 0
        else:
            return 1

        
    '''
    adds the public key to the central server to associate that public key. 
    '''    
    def addPublicKey(self):
        url = "http://cs302.kiwi.land/api/add_pubkey"

        # Generate a new random signing key
        hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)
        signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

        # dealing with public keys
        pubkey = signing_key.verify_key
        pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = pubkey_hex.decode('utf-8')

        #creating message and then signed
        message_bytes = bytes(pubkey_hex_str + self.username, encoding='utf-8')
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')

        headers = self.createAuthorisedHeader(True)
        payload = {
            "pubkey" : pubkey_hex_str,
            "username" : self.username,
            "signature" : signature_hex_str
        }
        
        JSON_object = helper.postJson(payload, headers, url)

        response = JSON_object.get("response", None)
        login_server_record = JSON_object.get("loginserver_record", None)
     
        if response == "ok" and login_server_record is not None:
            print("pubkey added successfully!")
            self.signing_key = signing_key
            self.hex_key = hex_key
            self.login_server_record = login_server_record
            #database.addLoginServerRecord(self.username, login_server_record)
            return 0
        else:
            print ("Failed to add pubkey")
            return 1

    '''
    returns the private data from get_privatedata in a JSON format
    doesnt need to be decrypted.
    '''
    def getPrivateData(self):
        url_get = "http://cs302.kiwi.land/api/get_privatedata"
        headers = self.createAuthorisedHeader(True)

        JSON_object = helper.postJson(None, headers, url_get)
        response = JSON_object.get("response", None)

        private_data = {}
        if response == "ok":
            private_data_encr = JSON_object.get("privatedata", None)
            if not private_data_encr:
                return {}
            private_data_bytes = base64.b64decode(private_data_encr)
            key = helper.getSymmetricKeyFromPassword(self.password2)
            try:
                private_data_str = helper.decryptStringKey(key, private_data_bytes)
            except nacl.exceptions.CryptoError as e: #TODO change to specific exception
                print(e)
                return {}
            else: 
                private_data = json.loads(private_data_str)
        return private_data

    '''
    adds the public key to the private data
    where private data input is the existing private data
    returns '0' if added successfully, otherwise error. 
    '''
    def addPrivateData(self, private_data):
        url_add = "http://cs302.kiwi.land/api/add_privatedata"
            
        headers = self.createAuthorisedHeader(True)
    
        ts = str(time.time())

        private_data_str = json.dumps(private_data)
        key = helper.getSymmetricKeyFromPassword(self.password2)
        private_data_encr = helper.encryptStringKey(key, private_data_str) #encrypted private data
        private_data_hex_str = base64.b64encode(private_data_encr).decode('utf-8') #hexed private data

        #creating message and then signed
        message_bytes = bytes(private_data_hex_str + self.login_server_record + ts, encoding='utf-8')
        signed = self.signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')

        payload = {
            "privatedata": private_data_hex_str,
            "loginserver_record": self.login_server_record,
            "client_saved_at": ts,
            "signature": signature_hex_str
        }

        JSON_object = helper.postJson(payload, headers, url_add)
        response = JSON_object.get("response", None)
        if response == "ok":
            print("added to private data successfully!")
            return 0
        else:
            print ("Failed to save private data")
            return 1

    '''
    gets api key for this session. 
    '''
    def getNewApiKey(self):
        url = "http://cs302.kiwi.land/api/load_new_apikey"
        headers = self.createAuthorisedHeader(True)
        JSON_object = helper.postJson(None, headers, url)

        response = JSON_object.get("response", None)
        if response == "ok":
            apikey = JSON_object.get("api_key", None)
            self.apikey = apikey
        if apikey is None or response != "ok":
            print("NO API KEY")
            return 1
        filename = "tmp/api.txt"
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w") as f:
                f.write(apikey)
        return 0

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
            

    '''
    sends a POST/GET request to the URL endpoint specified.
    returns the JSON response
    ''' 
    def postJson(self, payload, headers, url):

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
    def authoriseUserLogin(self):
        print("Log on attempt from {0}:{1}".format(self.username, self.password))
        if (self.username.lower() == "lche982") and (self.password.lower() == "lucycy98_864045152"):
            print("Success")
            return 0
        else:
            print("Failure")
            return 1