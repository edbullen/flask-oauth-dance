# SQLAlchemy database initialised in the __init__.py module
from app import db

# A Flask-Dance blueprint has a backend associated with it - object that knows how to store and retrieve OAuth tokens
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin
from flask_login import UserMixin


# Database schema
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(256), unique=True)
    username = db.Column(db.String(256), unique=True)

    # Define the relationship to Role via UserRoles
    roles = db.relationship('Role', secondary='user_roles')

    # test if a user is in the admin role
    @property
    def is_admin(self):
        roles = [r.name for r in self.roles]
        if "admin" in roles:
            return True
        else:
            return False


# User-ID is linked to their OAuth identity provider
class OAuth(OAuthConsumerMixin, db.Model):
    provider_user_id = db.Column(db.String(256), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User)


# Define the Role data-model
class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)


# Define the UserRoles association table
class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE'))
