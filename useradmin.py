from app import app

# User admin utilities
from app import utils

import argparse
import random
import string


if __name__ == '__main__':
    """Server-Side management of application user details stored in the database

    args [-a | lu | lr ] [ -r <role_to_add>]
    """


    parser = argparse.ArgumentParser(description="Add and list users and roles",
                                     formatter_class=argparse.RawTextHelpFormatter)
    # Add / List / Delete
    parser_action_group = parser.add_mutually_exclusive_group(required=True)

    parser_action_group.add_argument('-a', dest='add', action='store_true', help='Add')
    parser_action_group.add_argument('-d', dest='del', action='store_true', help='Delete')
    parser_action_group.add_argument('-lu', dest='list_users', action='store_true', help='List Users')
    parser_action_group.add_argument('-lr', dest='list_roles', action='store_true', help='List Roles')

    parser.add_argument('-r', dest='role_name', action='store', help='Role name', required=False)
    parser.add_argument('-e', dest='email', action='store', help='Email ID', required=False)


    args = vars(parser.parse_args())

    # fix for "No application found. Either work inside a view function or push an application context"
    with app.app_context():

        if args["add"]:
            if args["role_name"] and not args["email"]:
                role_name = args["role_name"]
                # add a new role
                utils.add_role(role_name)
            # add a user to a role
            elif args["role_name"] and args["email"]:
                utils.add_user_to_role(args["email"], args["role_name"])


        if args["list_users"]:
            utils.get_users()

        if args["list_roles"]:
            if args["email"]:
                utils.get_user_roles(args["email"])
            else:
                utils.get_roles()

        if args["del"]:
            if args["role_name"] and not args["email"]:
                role_name = args["role_name"]
                # add a new role
                utils.del_role(role_name)
            # add a user to a role
            elif args["role_name"] and args["email"]:
                utils.del_user_from_role(args["email"], args["role_name"])


