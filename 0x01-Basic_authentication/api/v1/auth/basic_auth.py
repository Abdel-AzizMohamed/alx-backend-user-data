#!/usr/bin/env python3
"""Define basic_auth class that mange basic authentication"""
import base64
import binascii
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

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """returns the decoded value of a Base64 string"""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decode_64 = base64.b64decode(
                base64_authorization_header, validate=True
            )
        except (binascii.Error, UnicodeDecodeError):
            return None
        return decode_64.decode("utf-8")
