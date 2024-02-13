#!/usr/bin/env python3
"""Define auth class that mange authentication"""

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
        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """Unimplemented"""
        return None
