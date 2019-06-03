import database
import time
import nacl.encoding
import nacl.signing

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