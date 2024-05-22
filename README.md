# PythonUserDatabase
A python database handler that gives a lot of basic functionality needed for registering, loging and manipulatiing user data for a basic webserver or someshit

## Functions

User login -> success, usertoken
User register -> success, usertoken

Get User data -> dict
Set User data -> bool (success)
Add User data -> bool (success)

Hash password -> str
is Valid Token -> bool

Static Functions
contains special -> bool
config str -> str


## Example usage
```
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

```
