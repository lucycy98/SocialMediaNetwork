import sqlite3
import os.path


def closeDatabase(conn):
    conn.commit()
    conn.close()

def initialiseTable(c, conn):
    # Creating a table for message archive and accounts info storage
    c.execute("CREATE TABLE users (username STRING PRIMARY KEY, address STRING, location STRING, pubkey STRING, lastReport STRING, status STRING)")
    c.execute("CREATE TABLE userhashes (username STRING NOT NULL, hash STRING, loginrecord STRING)")  
    
    c.execute("CREATE TABLE broadcasts (loginserver_record STRING NOT NULL, message STRING, sender_created_at INT(11), signature STRING)") 
    c.execute("CREATE TABLE receivedMessages (target_username STRING NOT NULL, target_pubkey STRING NOT NULL, encrypted_message STRING, sender_created_at INT(11), signature STRING, sender_username STRING, sent STRING)") 
    c.execute("CREATE TABLE sentMessages (username STRING NOT NULL, target_username STRING, message STRING, sender_created_at INT(11), sent STRING)") 

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
        print(result) #check if password matches #TODO update this to reflect result
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

def getConversation(username, otherUsername):
    conn, c = loadDatabase()

    query = """ SELECT message, sender_created_at, sent 
                FROM sentMessages 
                WHERE username='{username}' AND target_username='{target_username}'
                    UNION ALL
                SELECT encrypted_message, sender_created_at, sent 
                FROM receivedMessages 
                WHERE target_username='{username}' AND sender_username='{target_username}'
                ORDER BY sender_created_at ASC""".format(target_username=otherUsername, username=username)
    
    c.execute(query)
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

    
def getAllSentMessages(username, target_username, since=None):
    conn, c = loadDatabase()
    if not since: 
        c.execute("SELECT message, sender_created_at FROM sentMessages WHERE username = {a} AND target_username = {target_username} ORDER BY sender_created_at DESC".format(target_username=target_username, a=username))
    else:
        c.execute("SELECT sender_created_at FROM broadcasts WHERE username = {a} AND target_username = {target_username} AND sender_created_at > {since} ORDER BY sender_created_at DESC".format(since=since, target_username=target_username, a=username))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

#get all broadcasts since....
def getAllBroadcasts(since=None):
    conn, c = loadDatabase()
    if not since: 
        c.execute("SELECT * FROM broadcasts")
    else:
        c.execute("SELECT * FROM broadcasts WHERE sender_created_at > {since}".format(since=since))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

#get all messages since....
def getAllMessages(since=None):
    conn, c = loadDatabase()
    if not since: 
        c.execute("SELECT * FROM receivedMessages")
    else:
        c.execute("SELECT * FROM receivedMessages WHERE sender_created_at > {since}".format(since=since))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data

#get all messages since....for internal use.
def getSpecificMessages(username, sender_username, since=None):
    conn, c = loadDatabase()
    if not since: 
        c.execute("SELECT encrypted_message, sender_created_at FROM receivedMessages WHERE target_username = '{a}' AND sender_username= '{b}' ORDER BY sender_created_at DESC".format(a=username, b=sender_username))
    else:
        c.execute("SELECT encrypted_message, sender_created_at FROM receivedMessages WHERE sender_created_at > {since} AND target_username = '{a}' AND sender_username= '{b}' ORDER BY sender_created_at DESC".format(since=since, a = username, b=sender_username))
    result = c.fetchall()
    if len(result) == 0:
        closeDatabase(conn)
        return None
    data = resultToJSON(result, c)
    closeDatabase(conn)
    return data


def addReceivedMessage(target_username, target_pubkey, encrypted_message, timestamp , signature, their_username):
    conn, c = loadDatabase()
    c.execute("INSERT INTO receivedMessages VALUES('{target_username}','{target_pubkey}','{encrypted_message}','{timestamp}','{signature}', '{a}', 'received')".format(a=their_username, target_username=target_username, target_pubkey=target_pubkey, encrypted_message=encrypted_message, timestamp=timestamp, signature=signature))
    closeDatabase(conn)

def addsentMessages(username ,target_username, message, timestamp):
    conn, c = loadDatabase()
    c.execute("INSERT INTO sentMessages VALUES('{username}','{target_username}','{message}','{timestamp}', 'sent')".format(username=username, target_username=target_username, message=message, timestamp=timestamp))
    closeDatabase(conn)

def addBroadCast(username, message, timestamp, signature):
    conn, c = loadDatabase()
    c.execute("INSERT INTO broadcasts VALUES('{username}','{message}','{timestamp}', '{signature}')".format(username=username, message=message, timestamp=timestamp, signature=signature))
    closeDatabase(conn)







def updateUsersInfo(username, address=None, location=None, pubkey=None, lastReport=None, status=None):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM users WHERE username='{username}'".format(username = username))
    result = c.fetchall()
    if len(result) == 0:
        c.execute("INSERT INTO users VALUES('{username}','{address}','{location}','{pubkey}','{lastReport}','{status}')".format(username = username, address = address, location = location, pubkey = pubkey, lastReport = lastReport, status = status))
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
    print("PRINTING DATABASES!!!!!!!!!!!!!!!!")
    printDatabase()


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
    c.execute("SELECT * FROM receivedMessages")
    result = c.fetchall()
    print("print database:")
    print(result)
    closeDatabase(conn)

'''gets data from a user through the username'''
def getUserData(username):
    printDatabase()
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

    c.execute("SELECT * FROM users")
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


