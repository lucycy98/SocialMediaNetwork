import database
import time

def recieveMessage(signing_key):
    target_username = 'lche982'
    sender_username = 'admin' #after signing etc.
    userdata = getUserData(username)
    user = database.getUserData(send_user)
    user_address = user.get("address", None)
    user_location = user.get("location", None)
    user_pubkey = user.get("pubkey", None)
    
    encr_message = self.encryptMessage(message, user_pubkey)
    loginserver_record = database.getUserInfo(send_user, "loginrecord")        
    print(loginserver_record)
    ts = str(time.time())
    database.addReceivedMessage(send_user, user_pubkey, encr_message, ts, None, sender_username) #sending myself a message.
