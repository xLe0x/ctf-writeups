![](Pasted%20image%2020250517160757.png)

So we provided with the source code.

insert.redis:
![](Pasted%20image%2020250517162153.png)
so we have different key:value in the redis database. we wan't that `flag`!


main.py:
```python
### IMPORTS ###
import flask, redis, os


### INITIALIZATIONS ###
app = flask.Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32).hex()
HOST = "redthis-redis"


### HELPER FUNCTIONS ###
def getData(key):
    db = redis.Redis(host=HOST, port=6379, decode_responses=True)
    value = db.get(key)
    return value

def getAdminOptions(username):
    adminOptions = []
    if username != None and username == "admin":
        db = redis.Redis(host=HOST, port=6379, decode_responses=True)
        adminOptions = db.json().get("admin_options", "$")[0]
    return adminOptions



### ROUTES ###
@app.route('/', methods=['GET'])
def root():
    username = flask.session.get('username')
    adminOptions = getAdminOptions(username)
    return flask.render_template('index.html', adminOptions=adminOptions)


# get quote 
@app.route('/get_quote', methods=['POST'])
def getQuote():
    username = flask.session.get('username')
    person = flask.request.form.get('famous_person')
    quote = [person, '']
    if "flag" in person and username != "admin":
        quote[1] = "Nope"
    else: 
        quote[1] = getData(person)
    adminOptions = getAdminOptions(username)
    return flask.render_template('index.html', adminOptions=adminOptions, quote=quote)


@app.route('/register', methods=['POST', 'GET'])
def register():
    # return register page 
    if flask.request.method == 'GET':
        error = flask.request.args.get('error')
        return flask.render_template('register.html', error=error)

    username = flask.request.form.get("username").lower()
    password = flask.request.form.get("password")

    ## error check
    if not username or not password:
        return flask.redirect('/register?error=Missing+fields')

    ## if username already exists return error
    isUser = getData(username)
    if isUser:
        return flask.redirect('/register?error=Username+already+taken')
    else:
        # insert new user and password
        db = redis.Redis(host=HOST, port=6379, decode_responses=True)
        # db.set(username, "User") # nah, we don't want to let you write to the db :)
        passwordKey = username + "_password"
        # db.set(passwordKey, password) # nah, we don't want to let you write to the db :)
        flask.session['username'] = username
        return flask.redirect('/')

@app.route('/login', methods=['POST', 'GET'])
def login():
     # return register page 
    if flask.request.method == 'GET':
        error = flask.request.args.get('error')
        return flask.render_template('login.html', error=error)
    
    username = flask.request.form.get("username").lower()
    password = flask.request.form.get("password")

    ## error check
    if not username or not password:
        return flask.redirect('/login?error=Missing+fields')
    
    # check username and password
    dbUser = getData(username)
    dbPassword = getData(username + "_password")
    
    if dbUser == "User" and dbPassword == password:
        flask.session['username'] = username
        return flask.redirect('/')
    return flask.redirect('/login?error=Bad+login')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337, debug=False, threaded=True)
```

So there are 3 main paths:
- `/get_qoute`
- `/login`
- `/register`

## `/register`

```python
# insert new user and password
db = redis.Redis(host=HOST, port=6379, decode_responses=True)
# db.set(username, "User") # nah, we don't want to let you write to the db :)
passwordKey = username + "_password"
# db.set(passwordKey, password) # nah, we don't want to let you write to the db :)
flask.session['username'] = username
return flask.redirect('/')
```

so the registration process doesn't insert the values in the database, but rather create the session cookie.

![](Pasted%20image%2020250517161334.png)
![](Pasted%20image%2020250517161351.png)

## `/login`

once registration, we don't have to login actually.

```python
# check username and password
dbUser = getData(username)
dbPassword = getData(username + "_password")
```

```python
def getData(key):
    db = redis.Redis(host=HOST, port=6379, decode_responses=True)
    value = db.get(key)
    return value
```

**so if the username is `admin` the key of the password is `admin_password`.**

## `/get_quote`

```python
@app.route('/get_quote', methods=['POST'])
def getQuote():
    username = flask.session.get('username')
    person = flask.request.form.get('famous_person')
    quote = [person, '']
    if "flag" in person and username != "admin":
        quote[1] = "Nope"
    else: 
        quote[1] = getData(person)
    adminOptions = getAdminOptions(username)
    return flask.render_template('index.html', adminOptions=adminOptions, quote=quote)
```

```python
person = flask.request.form.get('famous_person')
```

```python
quote[1] = getData(person)
```

hmm, so if we get a new quote it uses the `getData` function to get the value of the key `person`. what if we tried to change it to `admin_password`?

![](Pasted%20image%2020250517161921.png)
![](Pasted%20image%2020250517162011.png)
![](Pasted%20image%2020250517162051.png)

Awesome, so the password is `I_HopeYou4re8admin_iLoveTechn070g_9283910`, let's login!

![](Pasted%20image%2020250517162348.png)
![](Pasted%20image%2020250517162408.png)
ezz!