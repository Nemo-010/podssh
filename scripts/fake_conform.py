"""Two faults of the stand-in relay (scripts/fake-relay.py) that `podssh
relay conform` must find (T-713): `querytoken` takes a token in the query
string of `/connect/` as well as in its header, and mints a token of one
session at `/v1/mint?once=1`, as podssh's relay role does, so that the check
asks; `wrongclose` (scripts/fake_lazy.py) answers a client's Close before
the dial with 1011. Each other mode is the stand-in as before."""

import ipaddress
import urllib.parse

MODE = "normal"


def is_mint(path):
    """`/v1/mint`; and `/v1/mint?once=1` in the mode querytoken alone, so
    that the other modes answer it 404 as before."""
    return path == "/v1/mint" or (MODE == "querytoken" and path == "/v1/mint?once=1")


def minted(path, token, expires):
    """The answer of a mint: a token of one session says so."""
    body = {"token": token, "expires": expires, "scope": "forward"}
    if path.endswith("?once=1"):
        body["once"] = True
    return body


def token_ok(path, headers, token):
    """The token in the header; in the mode querytoken, in the query too."""
    if headers.get("x-relay-token") == token:
        return True
    if MODE != "querytoken":
        return False
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
    return query.get("token") == [token]


def link_local(host):
    """A link-local address, the metadata service's among them: refused in
    each mode, as the contract's policy refuses it, so that the stand-in
    never dials one for a check of a refusal."""
    try:
        return ipaddress.ip_address(host.strip("[]")).is_link_local
    except ValueError:
        return False
