#!/usr/bin/env python3
"""NetSentinel CLI Administrator Bootstrap Script.

Usage:
    python backend/bootstrap.py [--username USERNAME]

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


def main(app=None):
    parser = argparse.ArgumentParser(description="NetSentinel Administrator Bootstrap CLI")
    parser.add_argument("--username", "-u", default=None, help="Administrator username (default: env or admin)")
    parser.add_argument("--password", "-p", default=None, help="Administrator password (prompted if omitted)")
    parser.add_argument("--reset-password", action="store_true", help="Explicitly reset password for existing administrator")
    parser.add_argument("--resolve-multiple-admins", action="store_true", help="Resolve multiple administrator accounts to comply with single-Admin policy")
    parser.add_argument("--keep-admin", default=None, help="Username of administrator to retain when resolving multiple admins")
    args = parser.parse_args()

    if app is None:
        app, _ = create_app(start_capture=False)

    with app.app_context():
        # Handle resolution of multiple administrator accounts
        if args.resolve_multiple_admins:
            admins = User.query.filter_by(role=Role.ADMIN).order_by(User.id).all()
            if len(admins) <= 1:
                print(f"[NetSentinel] Database contains {len(admins)} administrator account(s). Single administrator policy is satisfied.")
                return

            print(f"[NetSentinel Warning] Detected {len(admins)} administrator accounts in database:")
            for a in admins:
                status = "ACTIVE" if a.is_active else "DISABLED"
                print(f"  - ID {a.id}: '{a.username}' (Status: {status})")

            keeper_name = args.keep_admin
            if not keeper_name:
                if sys.stdin.isatty():
                    default_keeper = admins[0].username
                    choice = input(f"Enter username to retain as the sole ADMIN [{default_keeper}]: ").strip()
                    keeper_name = choice if choice else default_keeper
                else:
                    keeper_name = admins[0].username
                    print(f"[NetSentinel] Non-interactive mode: retaining earliest administrator '{keeper_name}'.")

            norm_keeper = keeper_name.strip().lower()
            keeper = next((a for a in admins if a.username.lower() == norm_keeper), None)
            if not keeper:
                print(f"[NetSentinel Error] Specified keeper '{keeper_name}' is not in the list of administrator accounts.")
                sys.exit(1)

            demoted = []
            for a in admins:
                if a.id != keeper.id:
                    a.role = Role.ANALYST
                    demoted.append(a.username)

            try:
                db.session.commit()
                print(f"[NetSentinel Success] Account policy resolved: '{keeper.username}' is the sole ADMIN.")
                print(f"[NetSentinel Success] Demoted to ANALYST: {', '.join(demoted)}. No accounts or data were deleted.")
                from database import ensure_single_admin_constraint
                ensure_single_admin_constraint()
                return
            except Exception as ex:
                db.session.rollback()
                print(f"[NetSentinel Error] Failed to resolve multiple administrators: {ex}")
                sys.exit(1)

        username = args.username or os.environ.get("NETSENTINEL_ADMIN_USERNAME", "admin").strip()
        norm_username = username.strip().lower()
        existing = User.query.filter_by(username=norm_username).first()

        existing_admins = User.query.filter_by(role=Role.ADMIN).all()
        if existing_admins and (not existing or existing.role != Role.ADMIN) and not args.reset_password:
            admin_names = [a.username for a in existing_admins]
            print(f"[NetSentinel Error] An administrator account already exists ({', '.join(admin_names)}).")
            print("NetSentinel enforces a single administrator policy.")
            print(f"To reset password for an existing administrator, run:")
            print(f"    python backend/bootstrap.py --reset-password --username {admin_names[0]}")
            sys.exit(1)

        password = args.password or os.environ.get("NETSENTINEL_ADMIN_PASSWORD", "")

        if not password:
            if sys.stdin.isatty():
                prompt_label = f"Enter new password for '{norm_username}': " if existing else f"Enter initial password for '{norm_username}': "
                password = getpass.getpass(prompt_label)
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

        if existing:
            try:
                existing.set_password(password)
                existing.role = Role.ADMIN
                existing.is_active = True
                db.session.commit()
                print(f"[NetSentinel] Password reset successfully for administrator '{norm_username}'.")
            except Exception as ex:
                db.session.rollback()
                print(f"[NetSentinel Error] Failed to update administrator password: {ex}")
                sys.exit(1)
        else:
            user, create_err = AuthService.create_user(
                username=norm_username,
                password=password,
                role=Role.ADMIN,
                is_active=True,
            )
            if create_err:
                print(f"Error creating user: {create_err}")
                sys.exit(1)
            print(f"[NetSentinel] Successfully created initial administrator '{norm_username}'.")


if __name__ == "__main__":
    main()
