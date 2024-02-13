#!/usr/bin/env python3
"""Define basic_auth class that mange basic authentication"""
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """Basic-Authentication class"""

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """returns the Base64 part of the Authorization header"""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if authorization_header[:6] != "Basic ":
            return None
        return authorization_header[6:]
