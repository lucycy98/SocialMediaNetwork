import sqlite3
import os.path

class databases():
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.conn = None
        self.c = None
        self.loadDatabase()

    def initialiseTable(self):
        # Creating a table for message archive and accounts info storage
        self.c.execute("CREATE TABLE users (username STRING PRIMARY KEY, address STRING, location STRING, pubkey STRING, lastReport STRING, status STRING)")
        self.c.execute("CREATE TABLE userhashes (username STRING NOT NULL, hash STRING )")  
        self.conn.commit()  

    def loadDatabase(self):
        filename = self.username + "databases/data.sqlite"
        exists = os.path.isfile(filename)
        self.conn = sqlite3.connect(filename)
        self.c = self.conn.cursor()
        if not exists:
            self.initialiseTable()
   
    def checkUsernamePassword(self):
        self.c.execute("SELECT * FROM userhashes WHERE username='{username}'".format(username = self.username))
        result = self.c.fetchall()
        if len(result) > 0: #then doesn't exist
            print(result) #check if password matches #TODO update this to reflect result
            try:
                storedPassword = result[0][1]
            except:
                storedPassword = None
            if storedPassword is not None and self.password != storedPassword:
                return 1
        else:
            self.c.execute("INSERT INTO userhashes VALUES ('{username}','{password}')".format(username = self.username, password = self.password))
            self.conn.commit()
        return 0        


    def updateUsersInfo(self, username, address=None, location=None, pubkey=None, lastReport=None, status=None):
        self.c.execute("SELECT * FROM users WHERE username='{username}'".format(username = username))
        result = self.c.fetchall()
        print("result")
        if len(result) == 0:
            print("LENGTH IS 0")
            self.c.execute("INSERT INTO users VALUES('{username}','{address}','{location}','{pubkey}','{lastReport}','{status}')".format(username = username, address = address, location = location, pubkey = pubkey, lastReport = lastReport, status = status))
        else:
            self.c.execute("UPDATE users SET address='{address}', location='{location}',pubkey='{pubkey}',lastReport='{lastReport}',status='{status}' WHERE username='{username}'".format(address = address, location = location, pubkey = pubkey, lastReport = lastReport, status = status, username = username))
        self.conn.commit()  


    '''gets data from a user through the username'''
    def getUserData(self, username):
        self.c.execute(
                "SELECT * FROM users WHERE username='{username}'".format(username = username))
        result = self.c.fetchall()
        if len(result) == 0:
            print("NONE!!!")
            return None
        
        columns = [desc[0] for desc in self.c.description]
        user = dict(zip(columns, result[0]))

        print("USR ISSSSS")
        print(user)
        print("result is")
        print(result)
        return user

