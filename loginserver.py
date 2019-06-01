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

class loginserver():
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.signing_key = None
        self.connection_address = "47.72.146.59:8080"
        self.connection_location = "2"
        self.users = None
        self.apikey = None
        self.login_server_record = None
        self.getConnectionAddress()
        self.getNewApiKey()

    
    def getConnectionAddress(self):
        ip = urllib.request.urlopen('http://ipv4.icanhazip.com').read()
        self.connection_address = ip.rstrip().decode('utf-8')

        if '10.103' in self.connection_address:
            self.location = '0'
        else:
            self.location = '2'
    
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
        print(JSON_object)
        response = JSON_object.get("response", None)
        if response == "ok":
            print("reported successfully.")
            return 0
        else:
            print ("error in reporting")
            return 1

    '''
    gets the ACTIVE users who have done a report in the last 5 minutes to the login server. 
    #TODO : store in database
    '''
    def getUsers(self):
        headers = self.createAuthorisedHeader(True)
        url = "http://cs302.kiwi.land/api/list_users"
        JSON_object = helper.postJson(None, headers, url)
        print(JSON_object)
        response = JSON_object.get("response", None)
        if response == 'ok':
            self.users = JSON_object.get("users", None)
            if self.users is not None:
                self.loadUsersIntoDatabase()
            print("")
            print(type(self.users))
            return 0   
        else:
            return 1
    
    def loadUsersIntoDatabase(self):
        if self.users is None:
            print("DIDNT WORK!")
            return
            
        users = self.users
        for user in users:
            print(user)
            #if "username" not in user:
                #continue
            database.updateUsersInfo(user.get("username"), user.get("connection_address", None), user.get("connection_location", None), user.get("incoming_pubkey", None), user.get("connection_updated_at", None), user.get("status", None))
        database.printDatabase()
        user = database.getUserData("lche982")


    '''
    gets the ACTIVE users who have done a report in the last 5 minutes to the login server. 
    #TODO : update database
    '''
    def checkPublicKey(self, pubkey_str):
        headers = self.createAuthorisedHeader(True)
        url = "http://cs302.kiwi.land/api/list_users"
        req = "?pubkey=" + pubkey_str
        JSON_object = helper.postJson(None, headers, url+req)
        print(JSON_object)
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
        print(signature_hex_str)

        headers = self.createAuthorisedHeader(True)
        payload = {
            "pubkey" : pubkey_hex_str,
            "signature": signature_hex_str
        }
        
        JSON_object = helper.postJson(payload, headers, url)
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
    goes through the private data on the account, and checks if a signing key has already
    been created on the account. if yes, add that to the session. if not, create a new 
    signing key and update the private data.
    '''
    def getSigningKey(self):
        private_data = self.getPrivateData()
        hex_key = private_data.get("prikeys", None)
        error = 0
        if hex_key is None:
            #create a public key and add to private data
            self.addPublicKey()
            error = self.testPublicKey()
            self.addKeyPrivateData(private_data)
            print("HEX KEY IS NONE")
        else:
            self.signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
            self.hex_key = hex_key
            error = self.testPublicKey()
        
        if error > 0:
            print("an error occured in getting a public key from either the private data or created.")
        return error 
        
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

        print("authorise signature here is")
        print(signature_hex_str)

        headers = self.createAuthorisedHeader(True)
        payload = {
            "pubkey" : pubkey_hex_str,
            "username" : self.username,
            "signature" : signature_hex_str
        }
        
        JSON_object = helper.postJson(payload, headers, url)
        print(JSON_object)
        response = JSON_object.get("response", None)
        login_server_record = JSON_object.get("loginserver_record", None)
        print("LOGIN SEVER RECORD IS ")
        print(login_server_record)

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

    '''produces the symmetric key'''
    def getSecretKey(self):
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
    def encryptString(self, input):
        input_bytes = bytes(input, encoding='utf-8') 
        key = self.getSecretKey()
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
    def decryptString(self, input):
        key = self.getSecretKey()
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
    def getPrivateData(self):
        url_get = "http://cs302.kiwi.land/api/get_privatedata"
        headers = self.createAuthorisedHeader(True)

        JSON_object = helper.postJson(None, headers, url_get)
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
            private_data_str = self.decryptString(private_data_bytes)
            private_data = json.loads(private_data_str)
        return private_data

    '''
    adds the public key to the private data
    where private data input is the existing private data
    returns '0' if added successfully, otherwise error. 
    '''
    def addKeyPrivateData(self, private_data):
        url_add = "http://cs302.kiwi.land/api/add_privatedata"
            
        headers = self.createAuthorisedHeader(True)
        
        print("HEX KEY IS ")
        
        print(self.hex_key)
        print(type(self.hex_key))
        ts = str(time.time())

        private_data["prikeys"] = self.hex_key.decode('utf-8')
        private_data_str = json.dumps(private_data)
        private_data_encr = self.encryptString(private_data_str) #encrypted private data
        private_data_hex_str = private_data_encr.hex() #hexed private data

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
        print(JSON_object)
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
        print(JSON_object)
        response = JSON_object.get("response", None)
        if response == "ok":
            apikey = JSON_object.get("api_key", None)
            print(apikey)
            self.apikey = apikey
        if apikey is None:
            print("NO API KEY")
            return 1
        filename = "tmp/api.txt"
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w") as f:
                f.write(apikey)

    '''
    returns an authorised header
    '''
    def createAuthorisedHeader(self, needsAuthentication):

        if not needsAuthentication:
            headers = {
                'Content-Type' : 'application/json; charset=utf-8'
            }
            return headers

        if self.username is None or self.password is None:
            return None

        #create HTTP BASIC authorization header
        if self.username is not None: #change!!! TODO
            credentials = ('%s:%s' % (self.username, self.password))
            b64_credentials = base64.b64encode(credentials.encode('ascii'))
            headers = {
                'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
                'Content-Type' : 'application/json; charset=utf-8',
            }
        else: #create api key
            headers = {
                'X-username': self.username,
                'X-apikey' : self.apikey,
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