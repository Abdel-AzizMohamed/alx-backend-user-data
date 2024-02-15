#!/usr/bin/env python3
"""Define auth class that mange authentication"""
import os
from flask import request
from typing import List, TypeVar


class Auth:
    """Authentication class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Unimplemented"""
        if path is None or excluded_paths is None:
            return True

        for exclude_path in excluded_paths:
            if path.rstrip("/") == exclude_path.rstrip("/"):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Unimplemented"""
        if request is None:
            return None
        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar("User"):
        """Unimplemented"""
        return None

    def session_cookie(self, request=None):
        """returns a cookie value from a request"""
        if request is None:
            return None
        cookie_name = os.getenv("SESSION_NAME")
        return request.cookies.get(cookie_name)
