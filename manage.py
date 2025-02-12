import unittest
import getpass
from flask.cli import FlaskGroup
from src import app, db
from src.accounts.models import User

cli = FlaskGroup(app)

@cli.command("test")
def test():
    tests = unittest.TestLoader().discover("tests")
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        return 0
    else:
        return 1

@cli.command("create_admin")
def create_admin():
    email = input("Enter e-mail address: ")
    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Enter password again: ")
    if password != confirm_password:
        print("Passwords don't match")
        return 1
    try:
        user = User(email=email, password=password, is_admin=True)
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        print(f"Couldn't create admin user: {e}")


if __name__ == '__main__':
    cli()
