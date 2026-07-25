# Axiom reference seed

The seed is Axiom-owned directory data, not application data.

```bash
uv run --project seed python seed/seed_meridian.py
```

Required environment:

- `AXIOM_ADMIN_PASSWORD`

Optional environment:

- `AXIOM_BASE_URL` (default `http://localhost:8180`)
- `AXIOM_ADMIN_REDIRECT_URI` (default `http://localhost:5182/callback`)

The runner:

- signs in through Axiom's public Admin OIDC/PKCE client;
- creates missing Meridian workforce identities through `/users`;
- creates missing identity Groups through `/teams`;
- adds missing direct memberships through `/teams/{id}/members`;
- applies invited/deactivated lifecycle examples through `/users/{id}`; and
- reports created, unchanged and changed counts without printing credentials.

It never uses SQL. It generates an unusable random local password for each newly created directory
identity because the current pre-SCIM API requires that field. Those passwords are never printed or
persisted in the fixture; customer OIDC becomes the authentication authority under AXP-3.

The same `meridian_profile.py` data becomes the source for the inbound SCIM replay adapter under
AXP-4. Application-specific registration and roles do not belong here.
