"""Strict explicit callback origins; credentials and redirects are never addresses."""
from urllib.parse import urlsplit


def validate_callback_origin(origin: str, port: int) -> str:
    try:
        parts = urlsplit(origin)
        valid = (parts.scheme == "http" and parts.hostname and
                 parts.username is None and parts.password is None and
                 parts.port == port and 0 < port < 65536 and
                 not parts.path and not parts.query and not parts.fragment and
                 not any(character.isspace() for character in origin))
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("invalid or mismatched callback origin")
    return origin
