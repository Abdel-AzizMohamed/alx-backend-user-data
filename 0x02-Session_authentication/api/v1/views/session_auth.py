#!/usr/bin/env python3
"""Define session_auth class"""
import os
from flask import request, jsonify
from api.v1.views import app_views
from models.user import User


@app_views.route("/auth_session/login", methods=["POST"], strict_slashes=False)
def login() -> str:
    """login route"""
    email = request.form.get("email")
    password = request.form.get("password")

    if email is None or len(email) == 0:
        return jsonify({"error": "email missing"}), 400
    if password is None or len(password) == 0:
        return jsonify({"error": "password missing"}), 400

    try:
        user = User.search({"email": email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404

    if len(user) == 0:
        return jsonify({"error": "no user found for this email"}), 404
    if User.is_valid_password(user[0], password):
        from api.v1.app import auth

        session_id = auth.create_session(getattr(user[0], "id"))
        user_js = jsonify(user[0].to_json())
        user_js.set_cookie(os.getenv("SESSION_NAME"), session_id)
        return user_js

    return jsonify({"error": "wrong password"}), 401
