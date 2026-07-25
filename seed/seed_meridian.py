"""Idempotently seed Meridian directory data through Axiom's public APIs."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from collections import Counter
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from meridian_profile import GROUPS, USERS

BASE = os.environ.get("AXIOM_BASE_URL", "http://localhost:8180").rstrip("/")
REDIRECT = os.environ.get("AXIOM_ADMIN_REDIRECT_URI", "http://localhost:5182/callback")
ADMIN_USERNAME = os.environ.get("AXIOM_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("AXIOM_ADMIN_PASSWORD", "")


class CsrfParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.token: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "input" and values.get("name") == "_csrf" and values.get("value"):
            self.token = values["value"]


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def admin_token(client: httpx.Client) -> str:
    if not ADMIN_PASSWORD:
        raise RuntimeError("AXIOM_ADMIN_PASSWORD is required")
    metadata = client.get(f"{BASE}/.well-known/openid-configuration")
    metadata.raise_for_status()
    discovery = metadata.json()
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    state = b64url(secrets.token_bytes(24))
    nonce = b64url(secrets.token_bytes(24))
    login = client.get(
        f"{discovery['authorization_endpoint']}?{urlencode({
            'response_type': 'code',
            'client_id': 'axiom-admin',
            'redirect_uri': REDIRECT,
            'scope': 'openid profile email roles',
            'state': state,
            'nonce': nonce,
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
        })}",
        follow_redirects=True,
    )
    login.raise_for_status()
    csrf = CsrfParser()
    csrf.feed(login.text)
    if not csrf.token:
        raise RuntimeError("Axiom login did not return a CSRF token")
    response = client.post(
        f"{BASE}/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD, "_csrf": csrf.token},
        follow_redirects=False,
    )
    for _ in range(12):
        location = response.headers.get("location")
        if not location:
            raise RuntimeError(f"Axiom login stopped at HTTP {response.status_code}")
        target = urljoin(str(response.url), location)
        if target.startswith(REDIRECT):
            query = parse_qs(urlparse(target).query)
            if query.get("state") != [state] or not query.get("code"):
                raise RuntimeError("Axiom callback state/code contract failed")
            token = client.post(
                discovery["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "client_id": "axiom-admin",
                    "code": query["code"][0],
                    "redirect_uri": REDIRECT,
                    "code_verifier": verifier,
                },
            )
            token.raise_for_status()
            return str(token.json()["access_token"])
        response = client.get(target, follow_redirects=False)
    raise RuntimeError("Axiom login exceeded the redirect limit")


def main() -> None:
    counts: Counter[str] = Counter()
    with httpx.Client(timeout=30.0, follow_redirects=False) as client:
        headers = {"Authorization": f"Bearer {admin_token(client)}"}
        listed = client.get(f"{BASE}/users", headers=headers, params={"page": 0, "size": 100})
        listed.raise_for_status()
        existing_users = {item["id"]: item for item in listed.json()["content"]}

        groups_response = client.get(f"{BASE}/teams", headers=headers)
        groups_response.raise_for_status()
        existing_groups = {item["name"]: item for item in groups_response.json()}
        group_ids: dict[str, str] = {}
        for spec in GROUPS:
            current = existing_groups.get(spec["name"])
            if current is None:
                created = client.post(
                    f"{BASE}/teams",
                    headers=headers,
                    json={
                        "name": spec["name"],
                        "domainId": None,
                        "description": spec["description"],
                        "defaultRoles": [],
                        "segments": [],
                        "allowedDomains": [],
                    },
                )
                created.raise_for_status()
                current = created.json()
                counts["groups_created"] += 1
            else:
                counts["groups_unchanged"] += 1
            group_ids[spec["key"]] = str(current["id"])

        for spec in USERS:
            current = existing_users.get(spec["id"])
            if current is None:
                created = client.post(
                    f"{BASE}/users",
                    headers=headers,
                    json={
                        "id": spec["id"],
                        "username": spec["username"],
                        "email": spec["email"],
                        "password": secrets.token_urlsafe(36),
                        "attributes": {
                            "display_name": spec["display_name"],
                            "department": spec["department"],
                            "directory_source": "meridian-reference",
                            "external_id": spec["id"],
                            "lifecycle": spec["lifecycle"],
                            "admin_domains": [],
                        },
                    },
                )
                created.raise_for_status()
                current = created.json()
                counts["users_created"] += 1
            else:
                if current["username"] != spec["username"] or current["email"] != spec["email"]:
                    raise RuntimeError(f"identity drift for {spec['id']}")
                counts["users_unchanged"] += 1

            expected_active = spec["lifecycle"] == "active"
            if bool(current["isActive"]) != expected_active:
                changed = client.put(
                    f"{BASE}/users/{spec['id']}",
                    headers=headers,
                    json={"email": None, "isActive": expected_active, "attributes": None},
                )
                changed.raise_for_status()
                counts["lifecycle_changed"] += 1

        for spec in USERS:
            for group_key in spec["groups"]:
                group_id = group_ids[group_key]
                members = client.get(f"{BASE}/teams/{group_id}/members", headers=headers)
                members.raise_for_status()
                member_ids = {member["id"] for member in members.json()}
                if spec["id"] in member_ids:
                    counts["memberships_unchanged"] += 1
                    continue
                added = client.post(
                    f"{BASE}/teams/{group_id}/members",
                    headers=headers,
                    json={"userId": spec["id"]},
                )
                added.raise_for_status()
                counts["memberships_created"] += 1

    print("Meridian reference directory seed PASS")
    for key in sorted(counts):
        print(f"  {key}: {counts[key]}")


if __name__ == "__main__":
    main()
