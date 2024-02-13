"""Define auth class that mange authentication"""

from flask import request
from typing import List, TypeVar


class Auth:
    """Authentication class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Unimplemented"""
        return False

    def authorization_header(self, request=None) -> str:
        """Unimplemented"""
        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """Unimplemented"""
        return None
