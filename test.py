def testPrivateKey():
    private_data = {}
    private_data["prikeys"] = "this is a signing key"
    print("private data is ")
    print(private_data)
    #converting dict to string, and then to bytes format
    json_string = json.dumps(private_data)
    private_data_bytes = bytes(json_string, encoding='utf-8') 

     # This must be kept secret, this is the combination to your safe
    key = getSecretKey()
    print("key")
    print(key)
    # This is your safe, you can use it to encrypt or decrypt messages
    box = nacl.secret.SecretBox(key)
    # This is our message to send, it must be a bytestring as SecretBox will
    # treat is as just a binary blob of data.
    message = private_data_bytes
    # This is a nonce, it *MUST* only be used once, but it is not considered
    # secret and can be transmitted or stored alongside the ciphertext. A
    # good source of nonce is just 24 random bytes.
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    # Encrypt our message, it will be exactly 40 bytes longer than the original
    # message as it stores authentication information and nonce alongside it.
    encrypted = box.encrypt(message, nonce)
    print("encrypted is ")
    print(encrypted)
    print(type(encrypted))
    # Decrypt our message, an exception will be raised if the encryption was
    # tampered with or there was otherwise an error.
    print("trying to decrypt the message plaintext:")
    plaintext = box.decrypt(encrypted) #should be bytes
    print(plaintext)
    data = plaintext.decode("utf-8") 
    print('data is ')
    print(data)
    JSON_object = json.loads(data)    
    print("json obejct is ")
    print(JSON_object)


def secretBoxExample():
    # This must be kept secret, this is the combination to your safe
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    # This is your safe, you can use it to encrypt or decrypt messages
    box = nacl.secret.SecretBox(key)
    # This is our message to send, it must be a bytestring as SecretBox will
    # treat is as just a binary blob of data.
    message = b"The president will be exiting through the lower levels"
    # This is a nonce, it *MUST* only be used once, but it is not considered
    # secret and can be transmitted or stored alongside the ciphertext. A
    # good source of nonce is just 24 random bytes.
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    # Encrypt our message, it will be exactly 40 bytes longer than the original
    # message as it stores authentication information and nonce alongside it.
    encrypted = box.encrypt(message, nonce)
    # Decrypt our message, an exception will be raised if the encryption was
    # tampered with or there was otherwise an error.
    plaintext = box.decrypt(encrypted)   
   