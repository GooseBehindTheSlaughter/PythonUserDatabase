import sqlite3
import hashlib
import secrets
import re
import json

class UserDatabase:
    def __init__(self, db_name="user_database.db"):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.createTable()

    def createTable(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    token TEXT NOT NULL,
                    user_data TEXT
                )
            """)

    ## Register and login functions
    def registerUser(self, username:str, password:str):
        """
        Returns Success:bool, token:str:none
        """
        username = self.clean_input(username)
        password = self.clean_input(password)

        token = secrets.token_hex(32)
        hashedPassword = self.hashPassword(password)

        try:
            with self.conn:
                self.conn.execute("""
                    INSERT INTO users (username, password, token)
                    VALUES (?, ?, ?)
                """, (username.lower(), hashedPassword, token))
            return True, token
        except sqlite3.IntegrityError:
            return False, None 

    def login(self, username:str, password:str):
        """
        Returns Success:bool, token:str:none
        """
        username = self.clean_input(username)
        password = self.clean_input(password)
        hashedPassword = self.hashPassword(password)

        with self.conn:
            cursor = self.conn.execute("""
                SELECT token FROM users 
                WHERE username = ? AND password = ?
            """, (username.lower(), hashedPassword))
            result = cursor.fetchone()

        if result:
            return True, result[0]
        else:
            return False, None
    ## END

    ## Userdata functions
    def getUserData(self, token:str) -> dict:
        """Returns userdata:dict"""
        with self.conn:
            cursor = self.conn.execute("""
                SELECT id, username, user_data FROM users
                WHERE token = ?
            """, (token,))
            result = cursor.fetchone()

            if result:
                userID, username, user_data_json = result
                user_data = json.loads(user_data_json) if user_data_json else {}
                return {"id": userID, "username": username, "user_data": user_data}
            else:
                return None

    def setUserData(self, token:str, user_data:dict) -> bool:
        """Returns success or not, NOTE idk what this will do if you already have data in there best to use addUserData for now"""
        user_data_json = json.dumps(user_data)
        try:
            with self.conn:
                self.conn.execute("""
                    UPDATE users 
                    SET user_data = ?
                    WHERE token = ?
                """, (user_data_json, token))
            return True
        except sqlite3.Error:
            return False
        
    def addUserData(self,token:str ,newData:str) -> bool:
        """Merges the new data with current data, will currently overwrite same keys"""
        currentData = self.getUserData(token)

        if currentData == None:
            return False
        
        merged = {**currentData["user_data"], **newData}
        return self.setUserData(token, merged) ## idrk if this is gonna work well :shrug:
    ## END


    def hashPassword(self, password:str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()
    
    def isValidToken(self, token:str) -> bool:
        with self.conn:
            cursor = self.conn.execute("""
                SELECT username FROM users
                WHERE token = ?
            """, (token,))
            return bool(cursor.fetchone())

    @staticmethod
    def clean_input(input_str:str) -> str:
        """Cleans Input from basic SQL injection"""
        cleaned_input = re.sub(r'[;\'"\\]', '', input_str)
        cleaned_input = re.sub(r'--.*$', '', cleaned_input)
        return cleaned_input
    
    @staticmethod
    def contains_special(input_str:str) -> bool:
        """Checks if the string contains anything but 0-9 A-Z"""
        pattern = re.compile(r"[a^zA-Z0-9]")
        return bool(pattern.search(input_str))
    
    @staticmethod
    def config_str(input_str, removeSpecialChars:bool=False,removeWhitespace:bool=False) -> str:
        """sets the type to str and cleans the input"""
        input_str = str(input_str) # incase something fucks up

        if removeSpecialChars:
            pattern = re.compile(r"[a^zA-Z0-9]")
            input_str = pattern.sub("", input_str)

        if removeWhitespace:
            input_str = input_str.strip()
        return input_str # fuck me this is ugly but it works


if __name__ == "__main__":
    ## SOME EXAMPLE USAGE

    db = UserDatabase()
    db.registerUser("exampleuser", 123456)

    success, token = db.login("exampleuser", "123456")

    testData = {
        "age" : 25,
        "email" : "someemail@example.com"
    }
    
    if success:
        print("SUCCESSFULLY LOGGED IN, TOKEN:" + token)
        data = db.getUserData(token)
        print(data)

    else:
        print("Login failed :( ")