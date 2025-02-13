from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_user, login_required, logout_user, current_user
from src import bcrypt, db
from src.accounts.models import User
from .forms import LoginForm, RegisterForm, TwoFactorForm
from src.utils import get_b64encoded_qr_image

accounts_bp = Blueprint("accounts", __name__)

HOME_URL = "core.home"
SETUP_2FA_URL = "accounts.setup_two_factor_auth"
VERIFY_2FA_URL = "accounts.verify_two_factor_auth"

@accounts_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash("You are already registered!", "info")
            return redirect(url_for(HOME_URL))
        else:
            flash("You don't have 2-Factor Authentication enabled! Please, enable it first to login!", "info")
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("You registered. Welcome! Now you have to enable 2FA first to login.", "success")
        return redirect(url_for(SETUP_2FA_URL))
    return render_template("accounts/register.html", form=form)

@accounts_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash("You are already authenticated", "info")
            return redirect(url_for("core.home"))
        else:
            flash("You don't have 2-Factor Authentication enabled. Please, enable it first to login!", "info")
            return redirect(url_for(SETUP_2FA_URL))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, request.form["password"]):
            login_user(user)
            if not current_user.is_two_factor_authentication_enabled:
                flash("You don't have 2-Factor Authentication enabled. Please, enable it forst to login.", "info")
                return redirect(url_for(SETUP_2FA_URL))
            return redirect(url_for(VERIFY_2FA_URL))
        elif not user:
            flash("You are not registered. Please register.", "danger")
        else:
            flash("Invalid email and/or password", "danger")
    return render_template("accounts/login.html", form=form)

@accounts_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You were logged out", "success")
    return redirect(url_for("accounts.login"))

#@accounts_bp.route("/forgot_password")
#def forgot_password():
#    if current_user.is_authenticated:
#        flash("You are already authenticated", "info")
#        return redirect(url_for("core.home"))
#    form

@accounts_bp.route("/setup-2fa")
@login_required
def setup_two_factor_auth():
    secret = current_user.secret_token
    uri = current_user.get_authentication_setup_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)
    return render_template("accounts/setup-2fa.html", secret=secret, qr_image=base64_qr_image)

@accounts_bp.route("/verify-2fa", methods=["GET", "POST"])
@login_required
def verify_two_factor_auth():
    form = TwoFactorForm(request.form)
    if form.validate_on_submit():
        if current_user.is_otp_valid(form.otp.data):
            if current_user.is_two_factor_authentication_enabled:
                flash("2FA verification succesful. You are logged in!", "success")
            else:
                try:
                    current_user.is_two_factor_authentication_enabled = True
                    db.session.commit()
                    flash("2FA setup successful. You are now logged in!", "success")
                    return redirect(url_for(HOME_URL))
                except Exception:
                    db.session.rollback()
                    flash("2FA setup failed. Please try again.", "danger")
                    return redirect(url_for(VERIFY_2FA_URL))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for(VERIFY_2FA_URL))
    else:
        if not current_user.is_two_factor_authentication_enabled:
            flash("You don't have 2-Factor Authentication enabled. Please, enable it first.", "info")
            return render_template("accounts/verify-2fa.html", form=form)
