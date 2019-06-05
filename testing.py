import database
import time
import nacl.encoding
import nacl.signing
import base64
from nacl import pwhash, secret, utils
import nacl.hash
import helper

signing_key = nacl.signing.SigningKey.generate() #PRIVATE KEY!!!
pubkey = signing_key.verify_key
pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
message = "hi"
message_hm = helper.encryptMessage(message, pubkey_hex)

decrypted = helper.decryptMessage(message_hm, signing_key)
print(decrypted)




def idk():
        username = "lche982"
        print("creating group chats")
        #generating symmetric keys to be stored
        key = helper.generateRandomSymmetricKey()
        print(key)
        new = key.hex()
        print(new)
        message_bytes_hex = bytes.fromhex(new)
        print(message_bytes_hex)


def pwashtest():
        password = b"password"
        message = b"This is a message for Bob's eyes only"

        kdf = pwhash.argon2i.kdf
        salt = b'\xa3\x95\\\xec\x1cFpr8\xb7\x92\x7f\x18%)\x88'
        ops = pwhash.argon2i.OPSLIMIT_SENSITIVE
        mem = pwhash.argon2i.MEMLIMIT_SENSITIVE

        Alices_key = kdf(secret.SecretBox.KEY_SIZE, password, salt,
                        opslimit=ops, memlimit=mem)
        Alices_box = secret.SecretBox(Alices_key)
        nonce = utils.random(secret.SecretBox.NONCE_SIZE)
        print(salt)

        encrypted = Alices_box.encrypt(message, nonce)

        # now Alice must send to Bob both the encrypted message
        # and the KDF parameters: salt, opslimit and memlimit;
        # using the same kdf mechanism, parameters **and password**
        # Bob is able to derive the correct key to decrypt the message



        Bobs_key = kdf(secret.SecretBox.KEY_SIZE, password, salt,
                opslimit=ops, memlimit=mem)

        Bobs_box = secret.SecretBox(Bobs_key)
        received = Bobs_box.decrypt(encrypted)
        print(received.decode('utf-8'))

def testprivatekeys():
    broadcasts = database.getAllBroadcasts()
    for broadcast in broadcasts:
        login = broadcast.get("loginserver_record")
        message = broadcast.get("message")
        time = broadcast.get("sender_created_at")
        signature = broadcast.get("signature")

        login_info = login.split(',')
        username = login_info[0]
        pubkey = login_info[1]
        server_time = login_info[2]
        signature_str = login_info[3]

        signature_bytes = bytes(signature, encoding='utf-8')
        message= bytes(login+message+str(time), encoding='utf-8')
        message_bytes_hex = bytes(message.hex(),encoding='utf-8')
        print("message hex is ")
        print(message)
        pubkey_hex = bytes(pubkey,encoding='utf-8')
        verify_key = nacl.signing.VerifyKey(pubkey_hex, encoder=nacl.encoding.HexEncoder)
        print(verify_key.verify(message_bytes_hex, signature_bytes, encoder=nacl.encoding.HexEncoder))
