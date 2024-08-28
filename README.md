# PythonUserDatabase
A python database handler that gives a lot of basic functionality needed for registering, loging and manipulatiing user data for a basic webserver or someshit

A python database handler that gives a lot of functionality for handling users, i'm currently using this with [flask_login](https://pypi.org/project/Flask-Login/) in a test setting for user handling

Abilities, register user, login user, set some data about the user, see when they last logged in, gives each user an invite code, ability to delete user, set some data about the user in dict format

### Updates
```
Not very well documented but this latest version adds a lot of missing functionality
for example

Encryped the passwords using bcrypt instead of hashlib
Checks if the username already exists before trying to register
Functions now return what went wrong
Made the sql queries nicer to look at

A bunch more I didnt document

```


## Functions
```
database.login(username, password) -> success:bool, token:str, error_message:str
database.register(username,password) -> success:bool, token:str, error_message:str
database.remove_user(username) -> success:bool, error_message:str
```
#### User data 
```
database.get_user_data(token) -> data:dict
database.set_user_data(token, data) -> bool # This overwrites the current data, use add instead
database.add_user_Data(token, data) -> bool # Merges the current data and the new data
database.isValidToken(token) -> bool # Used to see if the token we give correspondes to a user in the database
```

## Example usage
```
database = UserDatabase()
success, token, register_error = .registerUser("exampleuser", 123456)

if not success:
    print(register_error)
    exit()

success, token, login_error = db.login("exampleuser", "123456")

testData = {
    "age" : 25,
    "email" : "some_email@example.com"
}

if success:
    print("SUCCESSFULLY LOGGED IN, TOKEN:" + token)
    data = database.getUserData(token)
    print(data)

else:
    print("Login failed :( ")
    print(error)

```
