"""
scripts/create_admin.py

One-time bootstrap for the very first admin user. POST /api/v1/auth/register
is admin-only by design (Section 31: no self-registration into a security
tool), which means something has to create the FIRST admin outside the
API — this script does that by writing directly to the database.

Usage:
    python scripts/create_admin.py --username admin --password <password>

Requires JWT_SECRET_KEY and DATABASE_URL to already be set in the
environment (same as running the API itself).
"""
from __future__ import annotations

import argparse
import getpass
import sys

from backend.auth import hash_password
from backend.db import models
from backend.db.session import SessionLocal


def main() -> int:
    parser = argparse.ArgumentParser(description="Create the first admin user for CloudPath AI.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", help="If omitted, you'll be prompted (safer — avoids shell history).")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")
    if len(password) < 8:
        print("[!] Password must be at least 8 characters.")
        return 1

    session = SessionLocal()
    try:
        existing = session.query(models.UserModel).filter_by(username=args.username).one_or_none()
        if existing:
            print(f"[!] User '{args.username}' already exists.")
            return 1

        user = models.UserModel(username=args.username, hashed_password=hash_password(password), role="admin")
        session.add(user)
        session.commit()
        print(f"[*] Created admin user '{args.username}'.")
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
