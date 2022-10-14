# initialise the Flask app
from flask import Flask, redirect, url_for, flash, render_template, session
from flask_mail import Mail

# SQL Alchemy imports
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.exc import NoResultFound

# manage changes to data schema with SQL Alchemy
from flask_migrate import Migrate

from flask_dance.contrib.google import make_google_blueprint, google
# Example - import other Flask OAuth blueprints here:
# from flask_dance.contrib.github import make_github_blueprint, github

# A Flask-Dance blueprint has a backend associated with it - object that knows how to store and retrieve OAuth tokens
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin, SQLAlchemyStorage

from flask_dance.consumer import oauth_authorized, oauth_error
from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user
)

# import exceptions for handling expired token, invalid grant type etc
from oauthlib.oauth2 import InvalidGrantError, TokenExpiredError

import os

# logging setup
import logging
from logging.handlers import RotatingFileHandler
from logging.config import dictConfig


# create a Flask application called app
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")

# log dir location
app.config["LOG_DIR"] = os.environ.get("FLASK_LOG_DIR")
app.config["PYTHON_LOGGER_LEVEL"] = os.environ.get("PYTHON_LOGGER_LEVEL", "INFO")

# Get the  “Client ID” and “Client Secret” from the "Credentials"->"Oauth 2.0 Client ID" in Google Console
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")


# Google OAUTH blueprint for handling auth via Google
google_bp = make_google_blueprint(scope=["profile", "email"])
app.register_blueprint(google_bp, url_prefix="/login")

# Workaround for Warning: Scope has changed from "profile email" to "". error in Chrome.
# https://stackoverflow.com/questions/28011269/flask-dance-error-scope-has-changed
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

# switch off SQLALCHEMY_TRACK_MODIFICATIONS warnings
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# setup database models
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///../sqllite/flask-users.db"
db = SQLAlchemy()
migrate = Migrate(app, db)
mail = Mail(app)

# import the database schema and the routes
from app import models, routes

from app.models import User
from app.models import OAuth
from app.models import Role
from app.models import UserRoles

from app.utils import count_users_in_role, add_user_to_role

# setup login manager - login view handles how users are redirected if not logged in.
login_manager = LoginManager()
login_manager.login_view = 'google.login'

# setup SQLAlchemy backend.  OAuth tokens are stored in database.  current_user is  a proxy provided by Flask-Login
google_bp.backend = SQLAlchemyStorage(OAuth, db.session, user=current_user)


# Creates an instance of User in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# create/login local user on successful OAuth login
@oauth_authorized.connect_via(google_bp)
def google_logged_in(google_bp, token):
    if not token:
        flash("Failed to log in with Google.", 'danger')
        return False

    try:
        #resp = google_bp.session.get("/user")
        resp = google.get("/oauth2/v1/userinfo")
        assert resp.ok, resp.text
    except (InvalidGrantError, TokenExpiredError) as e:  # or maybe any OAuth2Error
        return redirect(url_for("google.login"))

    if not resp.ok:
        flash("Failed to fetch user info from Google.", 'danger')
        return False

    login_info = resp.json()
    user_id = str(login_info["email"])

    # Find this OAuth token in the database, or create it
    query = OAuth.query.filter_by(
        provider=google_bp.name,
        provider_user_id=user_id,
    )
    try:
        oauth = query.one()
    except NoResultFound:
        oauth = OAuth(
            provider=google_bp.name,
            provider_user_id=user_id,
            token=token,
        )

    if oauth.user:
        login_user(oauth.user)

        # if there are no admin users yet, make this user admin
        admin_users = count_users_in_role("admin")
        if admin_users == 0:
            app.logger.info("Zero admin users - adding {} to admin".format(oauth.user.email))
            add_user_to_role(current_user.email, "admin")
        # flash("Successfully signed in with Google", "info")

    else:
        # Create a new local user account for this user
        user = User(
            # possibility some info is None
            email=login_info["email"],
            username=login_info["name"],
        )
        # Associate the new local user account with the OAuth token
        oauth.user = user
        # Save and commit our database models
        db.session.add_all([user, oauth])

        # if there are no admin users yet, make this user admin
        admin_users = count_users_in_role("admin")
        if admin_users == 0:
            add_user_to_role(current_user.email, "admin")

        db.session.commit()
        # Log in the new local user account
        login_user(user)
        flash("Successfully signed in with Google.", "info")

    # Disable Flask-Dance's default behavior for saving the OAuth token
    return False


# notify on OAuth provider error
@oauth_error.connect_via(google_bp)
def google_error(google_bp, error, error_description=None, error_uri=None):
    msg = (
        "OAuth error from {name}! "
        "error={error} description={description} uri={uri}"
    ).format(
        name=google_bp.name,
        error=error,
        description=error_description,
        uri=error_uri,
    )
    flash(msg, "danger")


# hook up extensions to app
db.init_app(app)
login_manager.init_app(app)


# Logging configuration
dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})


if not os.path.exists(app.config['LOG_DIR']):
    os.mkdir(app.config['LOG_DIR'])
file_handler = RotatingFileHandler(app.config['LOG_DIR'] + "/flask_app.log", maxBytes=10240,
                                   backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
if app.config['PYTHON_LOGGER_LEVEL'] == 'DEBUG':
    file_handler.setLevel(logging.DEBUG)
else:
    file_handler.setLevel(logging.INFO)

app.logger.addHandler(file_handler)

if app.config['PYTHON_LOGGER_LEVEL'] == 'DEBUG':
    app.logger.setLevel(logging.DEBUG)
if app.config['PYTHON_LOGGER_LEVEL'] == 'WARNING':
    app.logger.setLevel(logging.WARNING)
else:
    app.logger.setLevel(logging.INFO)

app.logger.info('Flask Web Application Startup')


