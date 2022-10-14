from app import app
from flask import redirect, url_for, flash, render_template, session, request

# SQL Alchemy imports
# from flask_sqlalchemy import SQLAlchemy
# from sqlalchemy.orm.exc import NoResultFound

from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user, current_user
)

from functools import wraps

from app.models import User
from app.models import OAuth
from app.models import Role
from app.models import UserRoles

from app.forms import EditProfileForm, FindUsersForm

from app.utils import add_user_to_role
from app.utils import del_user_from_role

# db = SQLAlchemy()

# Decorator to check what role the user is in and return to /index if not a member
def access_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            roles = [r.name for r in current_user.roles]
            if role not in roles:
                flash("Permission Denied - not a member of the role \"{}\"".format(role), 'danger')
                return redirect(url_for('index'))
            return fn(*args, **kwargs)
        return decorated_view

    return wrapper


# logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    #flash("Successfully logged out", "info")
    return redirect(url_for("index"))


# landing page for authenticated and non-authenticated users
@app.route("/")
def index():

    return render_template("index.html")


# example of page that session has to be logged in to see
@app.route("/protected")
@login_required
def protected():
    roles = [r.name for r in current_user.roles]

    return render_template("protected.html", roles=roles)


# user profile
@app.route('/profile/<email>')
@login_required
def profile(email):
    u = User.query.filter_by(email=email).first_or_404()

    user_roles = [r.name for r in u.roles]
    all_roles = [r.name for r in Role.query.all()]

    session["user_email"] = u.email

    if current_user.email != u.email and not current_user.is_admin:
        flash("Permission Denied", 'danger')
        return redirect(url_for('index'))
    else:
        return render_template('profile.html', user_roles=user_roles, all_roles=all_roles, user=u)


# user profile edit
@app.route('/profile_edit', methods=['GET', 'POST'])
@login_required
@access_required(role="admin")
def profile_edit():

    u = User.query.filter_by(email=session.get("user_email")).first_or_404()
    user_roles = [r.name for r in u.roles]
    all_roles = [r.name for r in Role.query.all()]

    # Initialise the form with the users email, roles available, current roles
    form = EditProfileForm(u.email, all_roles, user_roles)

    if form.validate_on_submit():
        new_roles = request.form.getlist('rolescheckbox')
        # process new roles and add if necessary
        for nr in new_roles:
            if nr not in user_roles:
                add_user_to_role(u.email, nr)
                #flash("Added {} to role \"{}\"".format(u.email, nr), "info")
        # process existing roles and remove if necessary
        for xr in user_roles:
            if xr not in new_roles:
                del_user_from_role(u.email, xr)
                #flash("Removed {} from role \"{}\"".format(u.email, xr), "info")

        # refresh the user_roles
        user_roles = [r.name for r in u.roles]
        return render_template('profile.html'
                               , title='Profile'
                               , user_roles=user_roles
                               , all_roles=all_roles
                               , user=u)

    elif request.method == 'GET':
        form.email.data = u.email

        return render_template('profile_edit.html'
                               , title='Edit Profile'
                               , form=form
                               , user_roles=user_roles
                               , all_roles=all_roles
                               , user=u)
    else:
        flash('Form submit error', 'danger')
        for field_name, error_messages in form.errors.items():
            for err in error_messages:
                app.logger.error("profile_edit() form submit error - Field: {}, Message: {}".format(field_name, err))

    return render_template('profile_edit.html'
                           , form=form
                           , title='Edit Profile'
                           , user_roles=user_roles
                           , all_roles=all_roles
                           , user=u)


# example of page that session has to be logged in to see and the user has to be a member of group "admin"
@app.route("/find_users", methods=['GET', 'POST'])
@login_required
@access_required(role="admin")
def find_users():

    # Initialise the form with the users email, roles available, current roles
    form = FindUsersForm()

    return render_template("find_users.html", form=form)


# example of page that session has to be logged in to see and the user has to be a member of group "admin"
@app.route("/admin")
@login_required
@access_required(role="admin")
def admin():
    # app.logger.info("Testing Info Logging")
    # app.logger.warn("Testing Warn Logging")
    # app.logger.error("Testing Error Logging")

    return render_template("admin.html")


# example of page that session has to be logged in to see and the user has to be a member of group "user"
@app.route("/homepage")
@login_required
@access_required(role="user")
def homepage():
    return render_template("homepage.html")
