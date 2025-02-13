import pyotp
from datetime import datetime
from flask_login import UserMixin
from src import bcrypt, db
from config import Config

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    created_on = db.Column(db.DateTime, nullable = False)
    is_two_factor_authentication_enabled = db.Column(db.Boolean, nullable=False, default=False)
    secret_token = db.Column(db.String, unique=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, email, password, is_admin=False):
        self.email = email
        self.password = bcrypt.generate_password_hash(password)
        self.created_on = datetime.now()
        self.secret_token = pyotp.random_base32()
        self.is_admin = is_admin

    def get_authentication_setup_uri(self):
        return pyotp.totp.TOTP(self.secret_token).provisioning_uri(name=self.email, issuer_name=Config.APP_NAME)

    def is_otp_valid(self, user_otp):
        totp = pyotp.parse_uri(self.get_authentication_setup_uri())
        return totp.verify(user_otp)

    def __repr__(self):
        return f"<email {self.email}>"
