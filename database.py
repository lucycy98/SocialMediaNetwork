import sqlite3
import os.path


def closeDatabase(conn):
    conn.commit()
    conn.close()

def initialiseTable(c, conn):
    # Creating a table for message archive and accounts info storage
    c.execute("CREATE TABLE users (username STRING PRIMARY KEY, address STRING, location STRING, pubkey STRING, lastReport STRING, status STRING)")
    c.execute("CREATE TABLE userhashes (username STRING NOT NULL, hash STRING, loginrecord STRING)")  
    
    c.execute("CREATE TABLE broadcasts (loginserver_record STRING NOT NULL, message STRING, sender_created_at INT(11), signature STRING PRIMARY KEY, username STRING, meta STRING)") 
    c.execute("CREATE TABLE receivedMessages (target_username STRING NOT NULL, target_pubkey STRING NOT NULL, encrypted_message STRING, sender_created_at INT(11), signature STRING, sender_username STRING, sent STRING, loginserver_record STRING, meta STRING)") 
    c.execute("CREATE TABLE groups (groupkey_hash STRING NOT NULL, username STRING)")
    c.execute("CREATE TABLE groupMessages (groupkey_hash STRING, send_user STRING, group_message STRING, sender_created_at INT(11), received STRING, meta STRING)")
    c.execute("CREATE TABLE sentMessages (username STRING NOT NULL, target_username STRING, message STRING, sender_created_at INT(11), sent STRING, isGroup STRING)")
    c.execute("CREATE TABLE groupkeys (username STRING NOT NULL, groupkey_encr STRING)")

    c.execute("CREATE TABLE blockedUsers (username STRING, blockedUser STRING)")
    c.execute("CREATE TABLE blockedWords (username STRING, word STRING)")
    c.execute("CREATE TABLE favBroadcasts (username STRING, signature STRING, FOREIGN KEY(signature) REFERENCES broadcasts(signature) )")
    c.execute("CREATE TABLE blockedBroadcasts (username STRING, signature STRING, FOREIGN KEY(signature) REFERENCES broadcasts(signature) )")

    conn.commit()

def loadDatabase():
    filename = "databases/userdata.sqlite"
    exists = os.path.isfile(filename)
    conn = sqlite3.connect(filename)
    c = conn.cursor()
    if not exists:
        initialiseTable(c, conn)
    return conn, c


def checkUsernamePassword(username, password):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM userhashes WHERE username='{username}'".format(username = username))
    result = c.fetchall()
    if len(result) > 0: #then doesn't exist
        try:
            storedPassword = result[0][1]
        except:
            storedPassword = None
        if storedPassword is not None and password != storedPassword:
            closeDatabase(conn)
            return 1
    else:
        c.execute("INSERT INTO userhashes VALUES ('{username}','{password}', NULL)".format(username = username, password = password))
    closeDatabase(conn)

    return 0

def getNumberLikesBroadcasts(signature):
    conn, c = loadDatabase()
    c.execute("SELECT count (DISTINCT username) FROM favBroadcasts WHERE signature='{a}'".format(a = signature))
    result = c.fetchall()
    closeDatabase(conn)
    return result[0][0]

def getBlockedWords(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM blockedWords WHERE username='{a}'".format(a = username))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addBlockedWord(username, word):
    conn, c = loadDatabase()
    c.execute("INSERT INTO blockedWords VALUES('{a}', '{b}')".format(a=username, b=word))
    closeDatabase(conn)

def deleteBlockedWord(username, word):
    conn, c = loadDatabase()
    c.execute("DELETE FROM blockedWords WHERE username='{a}' AND word='{b}'".format(a=username, b=word))
    closeDatabase(conn)

def getBlockedUser(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM blockedUsers WHERE username='{a}'".format(a = username))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addBlockedUser(username, blockUser):
    conn, c = loadDatabase()
    c.execute("INSERT INTO blockedUsers VALUES('{a}', '{b}')".format(a=username, b=blockUser))
    closeDatabase(conn)

def deleteBlockedUser(username, user):
    conn, c = loadDatabase()
    c.execute("DELETE FROM blockedUsers WHERE username='{a}' AND blockedUser='{b}'".format(a=username, b=user))
    closeDatabase(conn)

def getBlockedBroadcasts(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM blockedBroadcasts, broadcasts WHERE blockedBroadcasts.username='{a}' AND blockedBroadcasts.signature = broadcasts.signature ORDER BY sender_created_at DESC".format(a = username))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def getAllBlockedBroadcasts():
    conn, c = loadDatabase()
    c.execute("SELECT * FROM blockedBroadcasts, broadcasts WHERE blockedBroadcasts.signature = broadcasts.signature ORDER BY sender_created_at DESC".format(a = username))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addBlockedBroadcast(username, signature):
    conn, c = loadDatabase()
    c.execute("INSERT INTO blockedBroadcasts VALUES('{a}', '{b}')".format(a=username, b=signature))
    closeDatabase(conn)

def getFavBroadcasts(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM favBroadcasts, broadcasts WHERE favBroadcasts.username='{a}' AND favBroadcasts.signature = broadcasts.signature ORDER BY sender_created_at DESC".format(a = username))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addFavBroadcast(username, signature):
    conn, c = loadDatabase()
    c.execute("INSERT INTO favBroadcasts VALUES('{a}', '{b}')".format(a=username, b=signature))
    closeDatabase(conn)

def addGroupKey(username, key_str):
    conn, c = loadDatabase()
    c.execute("INSERT INTO groupkeys VALUES('{a}', '{b}')".format(a=username, b=key_str))
    closeDatabase(conn)

def checkGroupKey(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM groupkeys WHERE username='{a}'".format(a = username))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return []
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def deleteGroupKey(username, groupkey):
    conn, c = loadDatabase()
    c.execute("DELETE FROM groupkeys WHERE username='{a}' AND groupkey_encr='{b}'".format(a=username, b=groupkey))
    closeDatabase(conn)

def getAllGroupChats(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM groups WHERE username='{a}'".format(a = username))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return []
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addGroupChatReceived(groupkey_hash, username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM groups WHERE groupkey_hash='{b}' AND username='{a}'".format(a = username, b=groupkey_hash))
    result = c.fetchall()
    if len(result) == 0:
        c.execute("INSERT INTO groups VALUES('{b}', '{a}')".format(a = username, b=groupkey_hash))
    closeDatabase(conn)
    

def getUserConversation(username, otherUsername):
    conn, c = loadDatabase()

    query = """ SELECT message, sender_created_at, sent 
                FROM sentMessages 
                WHERE username='{username}' AND isGroup='user' AND target_username='{target_username}'
                    UNION ALL
                SELECT encrypted_message, sender_created_at, sent 
                FROM receivedMessages 
                WHERE target_username='{username}' AND sender_username='{target_username}' AND meta='false'
                ORDER BY sender_created_at ASC""".format(target_username=otherUsername, username=username)
    
    c.execute(query)
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def getGroupConversation(username, group_hash):
    conn, c = loadDatabase()

    query = """ SELECT message, username, sender_created_at, sent 
                FROM sentMessages 
                WHERE username='{username}' AND isGroup='group' AND target_username='{group_hash}'
                    UNION ALL
                SELECT group_message, send_user, sender_created_at, received 
                FROM groupMessages 
                WHERE groupkey_hash='{group_hash}' AND send_user<>'{username}' AND meta='false'
                ORDER BY sender_created_at ASC""".format(group_hash=group_hash, username=username)
    print(query)
    c.execute(query)
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

#get all broadcasts since....
def getAllBroadcasts(since=None, checkMessages=None):
    conn, c = loadDatabase()
    if not since: 
        since = 0

    if not checkMessages:
        c.execute("SELECT * FROM broadcasts WHERE sender_created_at > {since} AND meta='false'".format(since=since))
    else:
        c.execute("SELECT loginserver_record, message, sender_created_at, signature FROM broadcasts WHERE sender_created_at > {since}".format(since=since))


    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

#get all broadcasts since....
def getAllBroadcastsUser(username):
    #printDatabase()
    conn, c = loadDatabase()
    c.execute("SELECT * FROM broadcasts WHERE username='{a}' AND meta='false'".format(a=username))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

#get all messages since....
def getAllMessages(since=None, checkMessages=None):
    conn, c = loadDatabase()
    if not since: 
        since = 0
    if not checkMessages:
        c.execute("SELECT * FROM receivedMessages WHERE sender_created_at > {since} AND meta='false'".format(since=since))
    else:
        c.execute("SELECT * FROM receivedMessages WHERE sender_created_at > {since}".format(since=since))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addReceivedMessage(target_username, target_pubkey, encrypted_message, timestamp , signature, their_username, loginrecord, meta):
    conn, c = loadDatabase()
    c.execute("INSERT INTO receivedMessages VALUES('{target_username}','{target_pubkey}','{encrypted_message}','{timestamp}','{signature}', '{a}', 'received', '{login}', '{meta}')".format(a=their_username, target_username=target_username, target_pubkey=target_pubkey, encrypted_message=encrypted_message, timestamp=timestamp, signature=signature, login=loginrecord, meta=meta))
    closeDatabase(conn)

def addGroupMessage(groupkey_hash, send_user, encrypted_message, timestamp, meta):
    conn, c = loadDatabase()
    c.execute("INSERT INTO groupMessages VALUES('{hash}','{send}','{encrypted_message}','{timestamp}','received', '{meta}')".format(hash=groupkey_hash, send=send_user, encrypted_message=encrypted_message, timestamp=timestamp, meta=meta))
    closeDatabase(conn)
    
def addsentMessages(username ,target_username, message, timestamp, group):
    conn, c = loadDatabase()
    c.execute("INSERT INTO sentMessages VALUES('{username}','{target_username}','{message}','{timestamp}', 'sent', '{group}')".format(username=username, target_username=target_username, message=message, timestamp=timestamp, group=group))
    closeDatabase(conn)

def addBroadCast(loginrecord, message, timestamp, signature, username, meta):
    conn, c = loadDatabase()
    c.execute("INSERT INTO broadcasts VALUES('{loginrecord}','{message}','{timestamp}', '{signature}', '{username}', '{meta}')".format(loginrecord = loginrecord, username=username, message=message, timestamp=timestamp, signature=signature, meta=meta))
    closeDatabase(conn)

def updateUsersInfo(username, address=None, location=None, pubkey=None, lastReport=None, status=None):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM users WHERE username='{username}'".format(username = username))
    result = c.fetchall()
    if len(result) == 0:
        q = "INSERT INTO users VALUES('{username}','{address}','{location}','{pubkey}','{lastReport}','{status}')".format(username = username, address = address, location = location, pubkey = pubkey, lastReport = lastReport, status = status)
        print(q)
        c.execute(q)
    else:
        c.execute("UPDATE users SET address='{address}', location='{location}',pubkey='{pubkey}',lastReport='{lastReport}',status='{status}' WHERE username='{username}'".format(address = address, location = location, pubkey = pubkey, lastReport = lastReport, status = status, username = username))
    closeDatabase(conn)

def makeUserOffline(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM users WHERE username='{username}'".format(username = username))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return
    else:
        c.execute("UPDATE users SET status='offline' WHERE username='{username}'".format(username=username))
    closeDatabase(conn)

def addLoginServerRecord( username, record):
    conn, c = loadDatabase()

    print("LOGIN SERVER METHOD")
    c.execute("SELECT * FROM userhashes WHERE username='{username}'".format(username = username))
    result = c.fetchall()
    if len(result) > 0:
        c.execute("UPDATE userhashes SET loginrecord='{record}' WHERE username='{username}'".format(record=record, username=username))
        print("adding login server record")
    closeDatabase(conn)


def getUserInfo( username, want):
    conn, c = loadDatabase()

    c.execute(
            "SELECT {want} FROM userhashes WHERE username='{username}'".format(want = want, username = username))
    result = c.fetchall()
    if len(result) == 0:
        
        return None
    else: 
        columns = [desc[0] for desc in c.description]
        user = dict(zip(columns, result[0]))
    closeDatabase(conn)
    return user.get(want, None)


def printDatabase():
    conn, c = loadDatabase()
    c.execute("SELECT * FROM broadcasts")
    result = c.fetchall()
    print("print database:")
    print(result)
    closeDatabase(conn)

'''gets data from a user through the username'''
def getUserData(username):
    #printDatabase()
    conn, c = loadDatabase()
    c.execute(
            "SELECT * FROM users WHERE username='{username}'".format(username = username))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    
    columns = [desc[0] for desc in c.description]
    user = dict(zip(columns, result[0]))
    closeDatabase(conn)
    return user

def getAllUsers():
    conn, c = loadDatabase()

    c.execute("SELECT * FROM users ORDER BY status DESC, username ASC")
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def getAllUsersStatus(status):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM users WHERE status = '{a}'".format(a=status))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data


def getAllUsersCondition(condition):
    conn, c = loadDatabase()
    query = "SELECT * FROM users {condition}".format(condition=condition)
    print(query)
    c.execute(query)
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def resultToJSON(result, c):
    data = []
    for row in result:
        columns = [desc[0] for desc in c.description]
        bc = dict(zip(columns, row))
        data.append(bc)
    return data


