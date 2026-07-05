"""AWS WAFv2 text transformations, applied in list order (matching real semantics:
each transformation is applied to the *output* of the previous one)."""
from __future__ import annotations

import html
import re
import urllib.parse

from .schema import TextTransformation

_CMD_LINE_CHARS = re.compile(r"[\"'()]")
_MULTI_SPACE = re.compile(r"\s+")


def _url_decode(value: str) -> str:
    return urllib.parse.unquote_plus(value)


def _html_entity_decode(value: str) -> str:
    return html.unescape(value)


def _compress_whitespace(value: str) -> str:
    return _MULTI_SPACE.sub(" ", value)


def _cmd_line(value: str) -> str:
    # Simplified CMD_LINE transform: strip quotes/parens and collapse whitespace,
    # matching AWS's documented intent of normalizing shell-style obfuscation.
    return _MULTI_SPACE.sub(" ", _CMD_LINE_CHARS.sub("", value))


_APPLIERS = {
    TextTransformation.NONE: lambda v: v,
    TextTransformation.LOWERCASE: lambda v: v.lower(),
    TextTransformation.URL_DECODE: _url_decode,
    TextTransformation.HTML_ENTITY_DECODE: _html_entity_decode,
    TextTransformation.COMPRESS_WHITE_SPACE: _compress_whitespace,
    TextTransformation.CMD_LINE: _cmd_line,
}


def apply_transformations(value: str, transformations: list[TextTransformation]) -> str:
    result = value
    for t in transformations:
        result = _APPLIERS[t](result)
    return result
