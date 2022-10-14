
# Flask OAUTH2 Quickstart Example


Based on the following:  
https://github.com/singingwolfboy/flask-dance-google   
Documentation:  
https://flask-dance.readthedocs.io/en/v0.8.3/quickstarts/google.html  

## Code Structure

```
 --|
   |--app/ 
       |--static/
       |--templates/
       | __init__.py
       | forms.py
       | models.py
       | routes.py
       | utils.py
   |
   |--logs/
   |--migrations/
   |--sqllite/
   |
   | flask-oauth.py
   | useradmin.py    
```



### User Mixin Integration Reference

https://flask-dance.readthedocs.io/en/v1.0.0/quickstarts/sqla-multiuser.html

# Roles 

If no other registered users are in the `admin` role, the next user logging in is added to `admin`. 

## Add Roles

Roles are managed in the `role` and `user_roles` tables.  

By default, two roles exist: `user` and `admin`.    

Pages / routes can be protected with the decorator `access_required()`. Example  
```python
# example of page where session has to be logged in to see and the user has to be a member of group "admin"
@app.route("/admin")
@login_required
@access_required(role="admin")
def admin():
    
    return render_template("admin.html")
```


## Manage Users and Roles outside the web application
Roles can be added and removed and users can be added to / removed from roles by using the `useradmin` tool.  This is a command-line utility that has to be run locally to the server environment.

- List roles: `./useradmin -lr`  
- Add a role: `./useradmin -a -r general`  
- Delete a role `./useradmin -d -r general`  
- Add a user to a role called *user* `./useradmin -a -e my.user@mail.com -r user`
- Remove a user from a role called *user* `./useradmin -d -e my.user@mail.com -r user`


# Google OAUTH Client Configuration

Google Cloud Console -> APIs and Services -> Credentials -> *"Create Credentials"* (in top menu)
  
Create a new `OAuth 2.0 Client ID`  

+ Authorized Javascript Origins -> set this to https://127.0.0.1:5000
+ Authorized redirect URIs -> set this to https://127.0.0.1:5000/login/google/authorized

API credential providers for OAuth are listed under  
*Cloud Console -> APIs and Services -> Credentials*  
in the `OAuth 2.0 Client IDs` section (a new provider configuration should appear there when it is created)

# Database Setup

Set `FLASK_APP` to the name of the python file that instantiates the Flask app.
```
export FLASK_APP=flask-oauth.py
```

Create a new migrate version scripts folder (`./migrations/versions`) :
```
flask db init
```
Ignore the message *"Please edit configuration/connection/logging settings in '/Users/ed.bullen/src/flask-oauth-dance/migrations/alembic.ini' before proceeding."*  
Usually it makes sense to check the contents of `./migrations` into the git repo.  

Create the scripts that build the schema (these are stored in `./migrations/versions`:
```commandline
flask db migrate -m "initialise database" 
```

Run the scripts to build the schema:
```commandline
flask db upgrade
```

# Run


```commandline
flask run
```

# Other notes

From the quick start:
   
*When you run this code locally, set the OAUTHLIB_INSECURE_TRANSPORT environment variable for it to work without HTTPS.   
You also must set the OAUTHLIB_RELAX_TOKEN_SCOPE environment variable to account for Google changing the requested OAuth scopes on you. 
For example, if you put this code in a file named google.py, you could run:*   
```commandline
$ export OAUTHLIB_INSECURE_TRANSPORT=1
$ export OAUTHLIB_RELAX_TOKEN_SCOPE=1
```


# Tests

Ref: https://flask-dance.readthedocs.io/en/latest/testing.html 


# Initial working quickstart code

Originally this code was just in the root directory in a file called `app.py`

`flask run --cert=adhoc` would successfully run it.

```python
import os
from flask import Flask, redirect, url_for
from flask_dance.contrib.google import make_google_blueprint, google
from oauthlib.oauth2 import InvalidGrantError, TokenExpiredError

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")

app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

google_bp = make_google_blueprint(scope=["profile", "email"])
app.register_blueprint(google_bp, url_prefix="/login")

@app.route("/")
def index():
    if not google.authorized:
        return redirect(url_for("google.login"))
    try:
        resp = google.get("/oauth2/v1/userinfo")
        assert resp.ok, resp.text
    except (InvalidGrantError, TokenExpiredError) as e:  # or maybe any OAuth2Error
        return redirect(url_for("google.login"))
    return "You are {email} on Google".format(email=resp.json()["email"])


if __name__ == "__main__":
    app.run(ssl_context="adhoc")

```



