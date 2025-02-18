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
import main
import threading

'''
this class deals with interaction with the login server
which includes authenticating users and reporting etc
''' 

class loginserver():
    def __init__(self, username, password, password2):
        self.username = username
        self.password = password
        self.signing_key = None
        self.connection_address = None
        self.connection_location = None
        self.users = None
        self.apikey = None
        self.login_server_record = None
        self.getConnectionAddress()
        self.hex_key = None
        self.password2 = password2
        self.status = "online"

    #temporary solution to clear private data except for private key when full
    def clearPrivateData(self):
        private_data = self.getPrivateData()
        values = private_data.get("prikeys", None)
        if not values:
            values = []
        signing_key = values[0]
        values = [signing_key]
        private_data["prikeys"] = values
        self.addPrivateData(private_data)

        
    '''
    Gets the connection address and location of the user
    '''        
    def getConnectionAddress(self):
        ip = urllib.request.urlopen('http://ipv4.icanhazip.com').read()
        publicip = ip.rstrip().decode('utf-8')

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
        #adding port 
        self.connection_address += ":" + str(main.LISTEN_PORT)
        print("MY IP IS")
        print(self.connection_address)
        print(self.connection_location)
    
    '''
    function to report the User. status can be offline, online, away, busy.
    '''
    def reportUser(self, status=None):

        print("reporting user" + str(self.username))
        headers = self.createAuthorisedHeader(True)
        url = "http://cs302.kiwi.land/api/report"
        pubkey = self.signing_key.verify_key
        pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = pubkey_hex.decode('utf-8')
        connection_address = self.connection_address
        connection_location = self.connection_location

        if not status:
            status = self.status

        payload = {
            "connection_address" :connection_address,
            "connection_location" : connection_location,
            "incoming_pubkey": pubkey_hex_str,
            "status": status
        }
        try: 
            JSON_object = helper.postJson(payload, headers, url)

            response = JSON_object.get("response", None)
            if response == "ok":
                return 0
            else:
                raise Exception("response not ok")
        except Exception as e:
            print(e)
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
        if private_data == 1:
            return 1 
        else:        
            prikeys = private_data.get("prikeys", None)
        
        if prikeys is None:
            self.addPublicKey()
            error = self.testPublicKey()
            if error != 0:
               return error
             #creating private data. 
            private_data["prikeys"] = []
            private_data["prikeys"].append(self.hex_key.decode('utf-8'))
            self.addPrivateData(private_data)
        else:
            hex_key = prikeys[0]
            self.signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
            self.hex_key = hex_key
            error = self.testPublicKey()
        self.getLoginServerRecord()
        if error > 0:
            print("an error occured in getting a public key from either the private data or created.")
        return error 

    '''
    gets the ACTIVE users who have done a report in the last 5 minutes to the login server. 
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
    
    '''
    gets the last reported users from login server and adds them to database. 
    if their username does not appear, make those users offline
    '''   
    def loadUsersIntoDatabase(self, reported_users):
        error = 0
        online_users = []
        for user in reported_users:
            username = user.get("username", None)
            status = user.get("status", None)
            online_users.append(user.get("username"))

            if not status:
                status = "online"
            er = database.updateUsersInfo(username, user.get("connection_address", None), user.get("connection_location", None), user.get("incoming_pubkey", None), user.get("connection_updated_at", None), status)
            if er.get("response", None) == "error":
                error = 1
        all_users = database.getAllUsers()

        for user in all_users:
            username = user.get("username", None)
            if username is None: 
                continue
            if username not in online_users:
                database.makeUserOffline(username)
        return error

    '''
    gets the ACTIVE users who have done a report in the last 5 minutes to the login server. 
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
    with the account.
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
            print(JSON_object)
            print(response)
            print(signature)
            print(pubkey_hex_str)
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
        try:
            JSON_object = helper.postJson(None, headers, url_get)
            response = JSON_object.get("response", None)
        except Exception as e:
            print(e)
            return {}
        else:
            private_data = {}
            if response == "ok":
                private_data_encr = JSON_object.get("privatedata", None)
                if not private_data_encr:
                    return {}
                private_data_bytes = base64.b64decode(private_data_encr)
                
                try:
                    key = helper.getSymmetricKeyFromPassword(self.password2)
                    private_data_str = helper.decryptStringKey(key, private_data_bytes)
                except nacl.exceptions.CryptoError as e:
                    print(e)
                    return 1
                except Exception as e:
                    print(e)
                    return 1
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
        print(len(private_data_hex_str))
        if len(private_data_hex_str) >= 4096:
            print("length of pd exceeds")
            self.clearPrivateData()
            return

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
        try: 
            JSON_object = helper.postJson(payload, headers, url_add)
            response = JSON_object.get("response", None)
            if response == "ok":
                print("added to private data successfully!")
                return 0
            else:
                raise Exception("failed to save private datta")
        except Exception as e:
            print(e)
            return 1


    '''
    gets api key for this session. 
    '''
    def getNewApiKey(self):
        url = "http://cs302.kiwi.land/api/load_new_apikey"
        headers = self.createAuthorisedHeader(True)
        try: 
            JSON_object = helper.postJson(None, headers, url)
            response = JSON_object.get("response", None)
            if response == "ok":
                apikey = JSON_object.get("api_key", None)
                self.apikey = apikey
            if not apikey or response != "ok":
                print("NO API KEY")
                return 1
        except Exception as e:
            print(e)
            return 1
        #filename = "tmp/api.txt"
        #os.makedirs(os.path.dirname(filename), exist_ok=True)
        #with open(filename, "w") as f:
                #f.write(apikey)
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

#---------------------Threading for continuous reporting & pinging and updating users--------------------------

class MyThread(threading.Thread):

    def __init__(self, logserv, peer):
        threading.Thread.__init__(self)
        self._stop = threading.Event()
        self.logserv = logserv
        self.p2p = peer

    def stop(self):
        self._stop.set()

    def stopped(self):
        print(self._stop.isSet())
        return self._stop.isSet()

    #periodically report the user, update database and ping check online users.
    def run(self):
        while not self.stopped():
            try:
                self.logserv.reportUser()
                self.logserv.getUsers()
                self.p2p.pingCheckUsers()
            finally:
                time.sleep(100)
