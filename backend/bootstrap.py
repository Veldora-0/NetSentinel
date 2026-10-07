#!/usr/bin/env python3
"""NetSentinel CLI Administrator Bootstrap Script.

Usage:
    python backend/bootstrap.py [--username USERNAME] [--password PASSWORD]

Allows secure initial administrator account creation or password reset
from the command line without hardcoding credentials in source code.
"""

import argparse
import getpass
import os
import sys

# Ensure backend directory is in sys.path
backend_dir = os.path.abspath(os.path.dirname(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app import create_app
from database import db
from auth.models import User
from auth.roles import Role
from auth.service import AuthService


def main():
    parser = argparse.ArgumentParser(description="NetSentinel Administrator Bootstrap CLI")
    parser.add_argument("--username", "-u", default=None, help="Administrator username (default: env or admin)")
    parser.add_argument("--password", "-p", default=None, help="Administrator password (prompted if omitted)")
    parser.add_argument("--role", "-r", default=Role.ADMIN, help="Role to assign (default: ADMIN)")
    args = parser.parse_args()

    app, _ = create_app(start_capture=False)

    with app.app_context():
        username = args.username or os.environ.get("NETSENTINEL_ADMIN_USERNAME", "admin").strip()
        password = args.password or os.environ.get("NETSENTINEL_ADMIN_PASSWORD", "")

        if not password:
            if sys.stdin.isatty():
                password = getpass.getpass(f"Enter password for '{username}': ")
                confirm = getpass.getpass("Confirm password: ")
                if password != confirm:
                    print("Error: Passwords do not match.")
                    sys.exit(1)
            else:
                print("Error: Password not provided and stdin is not interactive.")
                sys.exit(1)

        valid, err = AuthService.validate_password(password)
        if not valid:
            print(f"Error: {err}")
            sys.exit(1)

        norm_username = username.strip().lower()
        existing = User.query.filter_by(username=norm_username).first()

        if existing:
            existing.set_password(password)
            existing.role = args.role
            existing.is_active = True
            db.session.commit()
            print(f"[NetSentinel] Updated existing user '{norm_username}' (role: {args.role}).")
        else:
            user, create_err = AuthService.create_user(
                username=norm_username,
                password=password,
                role=args.role,
                is_active=True,
            )
            if create_err:
                print(f"Error creating user: {create_err}")
                sys.exit(1)
            print(f"[NetSentinel] Successfully created administrator '{norm_username}' (role: {args.role}).")


if __name__ == "__main__":
    main()
