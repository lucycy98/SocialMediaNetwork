import sqlite3
import os.path


def closeDatabase(conn):
    conn.commit()
    conn.close()

def initialiseTable(c, conn):
    # Creating a table for message archive and accounts info storage
    c.execute("CREATE TABLE users (username STRING PRIMARY KEY, address STRING, location STRING, pubkey STRING, lastReport STRING, status STRING)")
    c.execute("CREATE TABLE userhashes (username STRING NOT NULL, hash STRING, loginrecord STRING)")  
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


def updateUsersInfo(username, address=None, location=None, pubkey=None, lastReport=None, status=None):
    conn, c = loadDatabase()
    c.execute("SELECT * FROM users WHERE username='{username}'".format(username = username))
    result = c.fetchall()
    if len(result) == 0:
        c.execute("INSERT INTO users VALUES('{username}','{address}','{location}','{pubkey}','{lastReport}','{status}')".format(username = username, address = address, location = location, pubkey = pubkey, lastReport = lastReport, status = status))
    else:
        c.execute("UPDATE users SET address='{address}', location='{location}',pubkey='{pubkey}',lastReport='{lastReport}',status='{status}' WHERE username='{username}'".format(address = address, location = location, pubkey = pubkey, lastReport = lastReport, status = status, username = username))
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
    c.execute("SELECT * FROM users")
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
    data = []
    for row in result:
        columns = [desc[0] for desc in c.description]
        user = dict(zip(columns, row))
        print(user)
        data.append(user)
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
    data = []
    for row in result:
        columns = [desc[0] for desc in c.description]
        user = dict(zip(columns, row))
        print(user)
        data.append(user)
    closeDatabase(conn)
    return data



