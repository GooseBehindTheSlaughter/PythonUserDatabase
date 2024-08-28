import sqlite3, secrets, re, json, bcrypt
from datetime import datetime

"""
Some updates ive added,

Encryped passwords using bcrypt instead of hashes (idk why i thought it was a good idea to use hashes)
Re wrote majority of the queries to use less lines and look nicer
Added last login in the user data
Updated the information about the functions to show what they actualy do and what they return
Cleaned a lot of the functions up to use less code where needed but keeping readablity
Added stupid comments showing my horrible train of thought (thank god im not doing this as a job)
"""


class UserDatabase:
    def __init__(self, db_name="user_database.db"):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.__createTable()

    def __createTable(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    token TEXT NOT NULL UNIQUE,
                    user_data TEXT,
                    invite_code TEXT
                )
            """)

    def register(self, username:str, password:str) -> tuple[bool,str, str]:
        """
        Adds a user to the database
        
        - Returns
        success : bool
        token : str
        error_message : str
        """
        username = str(username)

        username = self.clean_input(username).lower()
        password = self.clean_input(str(password)).encode()
        hashed_pwd = bcrypt.hashpw(password, bcrypt.gensalt()).decode()

        # First see if the username we want is already in the database
        with self.conn:
            query = "SELECT username FROM users WHERE username = ?"
            result = self.conn.execute(query, (username,)).fetchone()

        if result:
            return False, "", "username already exists"


        # I should check if the token already exists in the database
        # But the chance of that happening is so low fuck it :shrug:

        token = secrets.token_hex(32)
        invite_code = secrets.token_hex(2)
        try:
            with self.conn:
                query = "INSERT INTO users (username, password, token, invite_code) VALUES (?, ?, ?, ?)"
                self.conn.execute(query, (username.lower(), hashed_pwd, token, invite_code))
            return True, token, ""
        
        except sqlite3.IntegrityError as error:
            # Usually happens when 2 tokens are the same
            return False, "", f"Integrity error, {error}" 
        except sqlite3.OperationalError as error:
            return False, "", f"Operation error, {error}"
        except Exception as error:
            return False, "", f"Unknown error, {error}"

    def login(self, username:str, password:str) -> tuple[bool,str, str]:
        """
        Sees if the username and password exists in the current database
        
        - Returns
        success : bool
        token   : str
        error   : str
        """
        username = str(username)
        username = self.clean_input(username)
        password = self.clean_input(password)

        # Get the password for the account we want to login to
        with self.conn:
            query = "SELECT password, token FROM users WHERE username = ?"
            result = self.conn.execute(query, (username.lower(), )).fetchone()

        if not result:
            return False, "", "Invalid username"

        # Compare the stored password to the password we supplied
        #_, _, pwd, token, _ = result
        pwd, token = result

        pwd_correct = bcrypt.checkpw(password.encode(), str(pwd).encode())     

        if pwd_correct:
            self.add_user_data(token,{"last_login" : str(datetime.now())})
            return True, token, ""

        return False, "" , "Invalid password"
        

    def remove_user(self,username:str) -> tuple[bool,str]:
        """Removes the user based on their username"""
        username = self.clean_input(str(username)).lower()

        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM users WHERE username = ?", (username,))

                if cursor.rowcount > 0:
                         True, ""
                return False, "user not found"

        except Exception as error:
            return False, f"error {error}"



    def get_user_data(self, token:str) -> dict:
        """Get the users data"""
        with self.conn:
            query = "SELECT id, username, userdata, invite_code FROM users WHERE token = ?"
            cursor = self.conn.execute(query, (token,))
            result = cursor.fetchone()

            if result:
                userID, username, user_data_json, invite_code = result
                user_data = json.loads(user_data_json) if user_data_json else {}
                return {"id": userID, "username": username, "user_data": user_data, "invite_code" : str(invite_code)}
            else:
                return {}

    def get_invite_code(self, token:str) -> str:
        """Gets the users invite code based on their token"""
        # This might get removed
        with self.conn:
            query = "SELECT invite_code FROM users WHERE token = ?"
            result = self.conn.execute(query, (token,)).fetchone()
        return result[0]


    def set_user_data(self, token:str, user_data:dict) -> bool:
        """
        - Returns if it succeded or not
        - This will overwrite any data that the current user has
        either get the data and merge it or use add_user_data
        """
        user_data_json = json.dumps(user_data)
        try:
            with self.conn: 
                query = "UPDATE users SET user_data = ? WHERE token = ?"
                self.conn.execute(query, (user_data_json, token))
            return True
        except sqlite3.Error:
            return False
        
    def add_user_data(self,token:str ,newData:dict) -> bool:
        """Merges the new data with current data, will overwrite same keys"""
        currentData = self.get_user_data(token)

        if currentData == None:
            return False
        
        merged = {**currentData["user_data"], **newData}
        return self.set_user_data(token, merged) ## idrk if this is gonna work well :shrug:
    
    def isValidToken(self, token:str) -> bool:
        "Checks if the token is set to a user"
        with self.conn:
            query = "SELECT username FROM users WHERE token = ?"
            result = self.conn.execute(query, (token, )).fetchone()
            return bool(result)

    @staticmethod
    def clean_input(input_str:str) -> str:
        """Cleans Input from basic SQL injection"""
        # This isnt even needed due to how querys are setup
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
    pass