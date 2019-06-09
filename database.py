import sqlite3
import os.path


def closeDatabase(conn):
    conn.commit()
    conn.close()

def initialiseTable(c, conn):
    # Creating a table for message archive and accounts info storage
    c.execute("CREATE TABLE users (username STRING PRIMARY KEY, address STRING NOT NULL, location STRING NOT NULL, pubkey STRING NOT NULL, lastReport STRING NOT NULL, status STRING NOT NULL)")
    c.execute("CREATE TABLE userhashes (username STRING NOT NULL, hash STRING  NOT NULL, loginrecord STRING)")  
    
    c.execute("CREATE TABLE broadcasts (loginserver_record STRING NOT NULL, message STRING  NOT NULL, sender_created_at INT(11) NOT NULL, signature STRING PRIMARY KEY NOT NULL, username STRING NOT NULL, meta STRING NOT NULL)") 
    c.execute("CREATE TABLE receivedMessages (target_username STRING NOT NULL, target_pubkey STRING NOT NULL, encrypted_message STRING NOT NULL, sender_created_at INT(11) NOT NULL, signature STRING NOT NULL, sender_username STRING NOT NULL, sent STRING NOT NULL, loginserver_record STRING NOT NULL, meta STRING NOT NULL)") 
    c.execute("CREATE TABLE groups (groupkey_hash STRING NOT NULL, username STRING)")
    c.execute("CREATE TABLE groupMessages (groupkey_hash STRING NOT NULL, send_user STRING NOT NULL, group_message STRING NOT NULL, sender_created_at INT(11) NOT NULL, received STRING NOT NULL, meta STRING NOT NULL)")
    c.execute("CREATE TABLE sentMessages (username STRING NOT NULL, target_username STRING NOT NULL, message STRING NOT NULL, sender_created_at INT(11) NOT NULL, sent STRING NOT NULL, isGroup STRING NOT NULL)")
    c.execute("CREATE TABLE groupkeys (username STRING NOT NULL, groupkey_encr STRING)")

    c.execute("CREATE TABLE blockedUsers (username STRING NOT NULL, blockedUser STRING NOT NULL)")
    c.execute("CREATE TABLE blockedWords (username STRING NOT NULL, word STRING NOT NULL)")
    c.execute("CREATE TABLE favBroadcasts (username STRING NOT NULL, signature STRING NOT NULL, FOREIGN KEY(signature) REFERENCES broadcasts(signature) )")
    c.execute("CREATE TABLE blockedBroadcasts (username STRING NOT NULL, signature STRING NOT NULL, FOREIGN KEY(signature) REFERENCES broadcasts(signature) )")

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
    c.execute("SELECT * FROM userhashes WHERE username=?", (username))
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
        try: 
            c.execute("INSERT INTO userhashes (username, hash, loginrecord) VALUES (?, ?, ?)",(username, password, None))
        except Exception as e:
            print(e)
            print(e.__class__)
        finally:
            closeDatabase(conn)

    return 0

def getNumberLikesBroadcasts(signature):
    conn, c = loadDatabase()
    c.execute("SELECT count (DISTINCT username) FROM favBroadcasts WHERE signature=?", (signature))
    result = c.fetchall()
    closeDatabase(conn)
    return result[0][0]

def getBlockedWords(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM blockedWords WHERE username=?", (username))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addBlockedWord(username, word):
    conn, c = loadDatabase()
    c.execute("INSERT INTO blockedWords (username, word) VALUES (?,?)", (username, word))
    closeDatabase(conn)

def deleteBlockedWord(username, word):
    conn, c = loadDatabase()
    c.execute("DELETE FROM blockedWords WHERE username=? AND word=?", (username, word))
    closeDatabase(conn)

def getBlockedUser(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM blockedUsers WHERE username=?",(username))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addBlockedUser(username, blockUser):
    conn, c = loadDatabase()
    c.execute("INSERT INTO blockedUsers (username, blockedUser) VALUES (?,?)", (username, blockUser))
    closeDatabase(conn)

def deleteBlockedUser(username, user):
    conn, c = loadDatabase()
    c.execute("DELETE FROM blockedUsers WHERE username=? AND blockedUser=?",(username, user))
    closeDatabase(conn)

def getBlockedBroadcasts(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM blockedBroadcasts, broadcasts WHERE blockedBroadcasts.username=? AND blockedBroadcasts.signature = broadcasts.signature ORDER BY sender_created_at DESC",(username))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def getAllBlockedBroadcasts():
    conn, c = loadDatabase()
    c.execute("SELECT * FROM blockedBroadcasts, broadcasts WHERE blockedBroadcasts.signature = broadcasts.signature ORDER BY sender_created_at DESC")
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addBlockedBroadcast(username, signature):
    conn, c = loadDatabase()
    c.execute("INSERT INTO blockedBroadcasts (username, signature) VALUES (?,?)" (username, signature))
    closeDatabase(conn)

def getFavBroadcasts(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM favBroadcasts, broadcasts WHERE favBroadcasts.username=? AND favBroadcasts.signature = broadcasts.signature ORDER BY sender_created_at DESC",(username))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addFavBroadcast(username, signature):
    conn, c = loadDatabase()
    c.execute("INSERT INTO favBroadcasts (username, signature) VALUES(?,?)", (username, signature))
    closeDatabase(conn)

def addGroupKey(username, key_str):
    conn, c = loadDatabase()
    c.execute("INSERT INTO groupkeys ((username, groupkey_encr) VALUES(?,?)", (username, key_str))
    closeDatabase(conn)

def checkGroupKey(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM groupkeys WHERE username=?",(username))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return []
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def deleteGroupKey(username, groupkey):
    conn, c = loadDatabase()
    c.execute("DELETE FROM groupkeys WHERE username=? AND groupkey_encr=?",(username, groupkey))
    closeDatabase(conn)

def getGroupUsers(groupkey_hash):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM groups WHERE groupkey_hash=?",(groupkey_hash))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def getAllGroupChats(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM groups WHERE username=?",(username))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return []
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addGroupChatReceived(groupkey_hash, username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM groups WHERE groupkey_hash=? AND username=?",(username,groupkey_hash))
    result = c.fetchall()
    if len(result) == 0:
        c.execute("INSERT INTO groups (groupkey_hash, username) VALUES(?, ?)",(username, groupkey_hash))
    closeDatabase(conn)
    

def getUserConversation(username, otherUsername):
    conn, c = loadDatabase()

    query = """ SELECT message, sender_created_at, sent 
                FROM sentMessages 
                WHERE username=? AND isGroup='user' AND target_username=?
                    UNION ALL
                SELECT encrypted_message, sender_created_at, sent 
                FROM receivedMessages 
                WHERE target_username=? AND sender_username=? AND meta='false'
                ORDER BY sender_created_at ASC"""
    
    c.execute(query,(username, otherUsername, username, otherUsername))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def getGroupConversation(username, group_hash):
    conn, c = loadDatabase()

    query = """ SELECT message, username, sender_created_at, sent 
                FROM sentMessages 
                WHERE username=? AND isGroup='group' AND target_username=?
                    UNION ALL
                SELECT group_message, send_user, sender_created_at, received 
                FROM groupMessages 
                WHERE groupkey_hash=? AND send_user<>? AND meta='false'
                ORDER BY sender_created_at ASC"""
    print(query, (username, group_hash, group_hash, username))
    c.execute(query)
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

#get all broadcasts since....
def getAllBroadcasts(since=None, checkMessages=None):
    conn, c = loadDatabase()
    if not since: 
        since = 0

    if not checkMessages:
        c.execute("SELECT * FROM broadcasts WHERE sender_created_at >? AND meta='false'",(since))
    else:
        c.execute("SELECT loginserver_record, message, sender_created_at, signature FROM broadcasts WHERE sender_created_at > ?",(since))


    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

#get all broadcasts since....
def getAllBroadcastsUser(username):
    #printDatabase()
    conn, c = loadDatabase()
    c.execute("SELECT * FROM broadcasts WHERE username=? AND meta='false'",(username))
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

#get all messages since....
def getAllMessages(since=None, checkMessages=None):
    conn, c = loadDatabase()
    if not since: 
        since = 0
    if not checkMessages:
        c.execute("SELECT * FROM receivedMessages WHERE sender_created_at > ? AND meta='false'",(since))
    else:
        c.execute("SELECT * FROM receivedMessages WHERE sender_created_at > ?",(since))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def addReceivedMessage(target_username, target_pubkey, encrypted_message, timestamp , signature, their_username, loginrecord, meta):
    conn, c = loadDatabase()
    c.execute("""INSERT INTO receivedMessages VALUES 
    (target_username, target_pubkey, encrypted_message, sender_created_at, signature, sender_username, sent, loginserver_record, meta)
    VALUES (?,?,?,?,?,?,?,?,?)""", (target_username, target_pubkey, encrypted_message, timestamp, signature, their_username, "received", loginrecord, meta ))
    closeDatabase(conn)

def addGroupMessage(groupkey_hash, send_user, encrypted_message, timestamp, meta):
    conn, c = loadDatabase()
    c.execute("""INSERT INTO groupMessages 
    (groupkey_hash , send_user , group_message , sender_created_at, received , meta)
    VALUES(?,?,?,?,?,?)""",
    (groupkey_hash, send_user, encrypted_message, timestamp, 'received', meta))
    closeDatabase(conn)
    
def addsentMessages(username ,target_username, message, timestamp, group):
    conn, c = loadDatabase()
    c.execute("""INSERT INTO sentMessages 
    (username, target_username , message , sender_created_at, sent, isGroup)
    VALUES (?,?,?,?,?,?)""", 
    (username, target_username, message, timestamp, 'sent', group))
    closeDatabase(conn)

def addBroadCast(loginrecord, message, timestamp, signature, username, meta):
    conn, c = loadDatabase()
    c.execute("""INSERT INTO broadcasts 
    (loginserver_record, message , sender_created_at, signature , username, meta)
    VALUES (?,?,?,?,?,?)""",
    (loginrecord, message, timestamp, signature, username, meta))
    closeDatabase(conn)

def updateUsersInfo(username, address=None, location=None, pubkey=None, lastReport=None, status=None):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM users WHERE username=?",(username))
    result = c.fetchall()
    if len(result) == 0:
        q = """INSERT INTO users 
        (username, address , location , pubkey , lastReport , status )
        VALUES(?,?,?,?,?,?)"""
        c.execute(q, username, address, location, pubkey, lastReport, status)
    else:
        c.execute("UPDATE users SET address='{address}', location='{location}',pubkey='{pubkey}',lastReport='{lastReport}',status='{status}' WHERE username='{username}'",(address = address, location = location, pubkey = pubkey, lastReport = lastReport, status = status, username = username))
    closeDatabase(conn)

def makeUserOffline(username):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM users WHERE username=?",(username))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return
    else:
        c.execute("UPDATE users SET status='offline' WHERE username=?",(username))
    closeDatabase(conn)

def addLoginServerRecord( username, record):
    conn, c = loadDatabase()

    print("LOGIN SERVER METHOD")
    c.execute("SELECT * FROM userhashes WHERE username=?",(username))
    result = c.fetchall()
    if len(result) > 0:
        c.execute("UPDATE userhashes SET loginrecord=? WHERE username=?",(record, username))
        print("adding login server record")
    closeDatabase(conn)

'''gets data from a user through the username'''
def getUserData(username):
    #printDatabase()
    conn, c = loadDatabase()
    c.execute(
            "SELECT * FROM users WHERE username=?",(username))
    result = c.fetchall()   
    columns = [desc[0] for desc in c.description]
    user = dict(zip(columns, result[0]))
    closeDatabase(conn)
    return user

def getAllUsers():
    conn, c = loadDatabase()

    c.execute("SELECT * FROM users ORDER BY status DESC, username ASC")
    result = c.fetchall()
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

def getAllUsersStatus(status):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM users WHERE status =?",(status))
    result = c.fetchall()
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


