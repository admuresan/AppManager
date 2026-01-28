"""
Admin authentication routes (login/logout).

IMPORTANT: Read `instructions/architecture` before making changes.
"""

from flask import current_app, flash, redirect, render_template, request, url_for
from flask_login import login_required, login_user, logout_user

from app.models.user import User

from ..blueprint import bp


@bp.route("/login", methods=["GET", "POST"])
def login():
    """Admin login page."""
    # Get client IP address (handle proxy headers)
    ip_address = request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP", request.remote_addr))
    if ip_address:
        ip_address = ip_address.split(",")[0].strip()
    else:
        ip_address = request.remote_addr or None

    if request.method == "POST":
        # Check if IP is blocked before processing login
        from app.utils.login_security import is_ip_blocked, record_failed_attempt, reset_failed_attempts

        is_blocked, _remaining_attempts, block_message = is_ip_blocked(current_app.instance_path, ip_address)
        if is_blocked:
            flash(block_message, "error")
            return render_template("admin/login.html")

        username = request.form.get("username")
        password = request.form.get("password")

        user = User.get_by_username(username)
        if user and user.check_password(password):
            # Successful login - reset failed attempts
            reset_failed_attempts(current_app.instance_path, ip_address)

            # Track admin login
            try:
                from app.utils.traffic_tracker import add_admin_ip, track_admin_login

                if ip_address:
                    track_admin_login(current_app.instance_path, ip_address)
                    add_admin_ip(current_app.instance_path, ip_address)
            except Exception:
                pass  # Don't fail login if tracking fails

            login_user(user)
            return redirect(url_for("admin.dashboard"))

        # Failed login - record attempt
        is_now_blocked, _remaining_attempts, error_message = record_failed_attempt(current_app.instance_path, ip_address)
        if is_now_blocked:
            flash(error_message, "error")
        else:
            flash(f"Invalid username or password. {error_message}", "error")

    return render_template("admin/login.html")


@bp.route("/logout")
@login_required
def logout():
    """Logout admin."""
    logout_user()
    return redirect(url_for("welcome.index"))

