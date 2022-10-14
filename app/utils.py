from app import db, app

"""
Utilities for listing and managing users and roles
"""

# import the database schema
from app.models import User
from app.models import OAuth
from app.models import Role
from app.models import UserRoles


def add_role(role_name):
    """add a new role"""
    role = Role(name=role_name)
    db.session.add(role)
    db.session.commit()


def add_user_to_role(email, role_name):
    """add user to role"""
    user = User.query.filter_by(email=email).first()
    role = Role.query.filter_by(name=role_name).first()
    user.roles.append(role)
    db.session.commit()
    app.logger.info("Add user {} to role {}".format(email, role_name))


def get_roles():
    roles = Role.query.all()
    for r in roles:
        print(f"{r.id}, {r.name}")


def count_users_in_role(role_name):
    result = db.session.execute("""SELECT count(*)
                                    FROM user
                                    LEFT JOIN user_roles ON user.id = user_roles.user_id
                                    JOIN role ON role.id = user_roles.role_id
                                    WHERE role.name = :val""", {'val': role_name})
    count = int(result.fetchall()[0][0])
    return count


def get_users():
    users = User.query.all()
    for u in users:
        print(f"{u.email}, {u.username}")

def get_user_roles(email):
    user = User.query.filter_by(email=email).first()
    for r in user.roles:
        print(f"{r.id}, {r.name}")

def del_role(role_name):
    """remove a role"""
    role = Role.query.filter_by(name=role_name).first()
    db.session.delete(role)
    db.session.commit()

def del_user_from_role(email, role_name):
    """remove user from role"""
    user = User.query.filter_by(email=email).first()
    role = Role.query.filter_by(name=role_name).first()
    user.roles.remove(role)
    db.session.commit()
    app.logger.info("Remove user {} from role {}".format(email, role_name))




