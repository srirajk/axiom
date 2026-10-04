"""Customer (CIAM) helpers. Customers are a separate population from workforce users: different records, different
endpoints (``/ciam/tenants/{t}/customers``), different tokens (``identity_kind=customer``, audience
``axiom-token-exchange``) and no tenant or application roles.

Verification codes: Axiom ships no delivery provider. The cookbook estate enables Axiom's loopback-only local-demo
aid, which returns the e-mail verification code to the *customer's own* registration or verification-challenge call.
Every verification performed this way is labelled ``LOCAL_DEMO (simulated delivery)`` in the evidence; it proves the
verification endpoint, not that a message reached a mailbox. Recovery codes are never disclosed (recovery is
deferred until a provider exists).
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Iterable

from .context import Context, strong_password
from .http import Response
from .redaction import Secret

SIMULATED_DELIVERY = "LOCAL_DEMO (simulated delivery)"


@dataclass
class Customer:
    id: str
    email: str
    password: Secret
    record: dict


def base(ctx: Context) -> str:
    return f"/ciam/tenants/{ctx.tenant}/customers"


def _own(ctx: Context, customer_id: str) -> None:
    # Axiom has no customer delete; an ACTIVE customer is suspended at cleanup, a pending one stays pending
    # (it cannot authenticate). Both are reported as residuals of this run's namespace.
    ctx.registry.add("customer", customer_id, lambda: ctx.http.post(
        f"{ctx.admin_base()}/ciam/customers/{customer_id}/suspend", bearer=ctx.operator()),
        "suspend (no delete API); pending identities cannot authenticate")


def provision(ctx: Context, op: Secret, suffix: str) -> Customer:
    """Administrator provisioning (authenticated, tenant_admin). Starts PENDING_VERIFICATION; no code is returned."""
    email, password = f"{ctx.name(suffix)}@customers.cookbook.invalid", strong_password()
    r = ctx.http.post(f"{ctx.admin_base()}/ciam/customers", bearer=op, json_body={
        "email": email, "displayName": ctx.name(suffix), "initialPassword": password.reveal()}).expect(201).json()
    _own(ctx, r["customerId"])
    return Customer(r["customerId"], email, password, r)


def register(ctx: Context, suffix: str) -> tuple[Customer, dict]:
    """Self-registration (unauthenticated). Returns the customer and the response's delivery metadata only."""
    email, password = f"{ctx.name(suffix)}@customers.cookbook.invalid", strong_password()
    body = ctx.http.post(base(ctx) + "/registrations", json_body={
        "email": email, "displayName": ctx.name(suffix), "password": password.reveal()}).expect(201).json()
    _own(ctx, body["customer"]["customerId"])
    return Customer(body["customer"]["customerId"], email, password, body["customer"]), {
        "codeDelivery": body.get("codeDelivery"), "codeReturnedToCustomer": body.get("localDemoAction") is not None}


def request_verification(ctx: Context, customer: Customer) -> Secret | None:
    """The customer asks for a verification code. Locally the code comes back to the customer (simulated delivery)."""
    body = ctx.http.post(base(ctx) + "/verification-challenges", json_body={"email": customer.email}).expect(202).json()
    action = body.get("localDemoAction")
    return Secret(action["token"], "verification code") if action else None


def verify(ctx: Context, code: Secret) -> Response:
    return ctx.http.post(base(ctx) + "/verifications", json_body={"token": code.reveal()})


def verified(ctx: Context, op: Secret, suffix: str) -> Customer:
    """Provisioned by an administrator, then verified by the customer through the ordinary challenge."""
    customer = provision(ctx, op, suffix)
    code = request_verification(ctx, customer)
    if code is None:
        raise AssertionError("no verification channel: the estate needs a provider or the local-demo aid")
    customer.record = verify(ctx, code).expect(200).json()
    return customer


def token(ctx: Context, customer: Customer, client_id: str, scopes: Iterable[str]) -> Response:
    """Axiom's customer sign-in endpoint (JSON body; Axiom-specific, see O03). Returns an exchange-subject token."""
    return ctx.http.post(base(ctx) + "/tokens", json_body={
        "email": customer.email, "password": customer.password.reveal(), "clientId": client_id,
        "scopes": list(scopes)})


def access_token(response: Response) -> Secret:
    return Secret(response.expect(200).json()["accessToken"], "customer token")


def grant(ctx: Context, bearer: Secret, customer: Customer, workload_id: str, audience: str, scopes: list[str],
          purpose: str = "cookbook consent", purpose_code: str | None = None, seconds: int = 3600) -> Response:
    body = {"agentWorkloadId": workload_id, "audience": audience, "scopes": scopes, "purpose": purpose,
            "expiresAt": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)).isoformat()}
    if purpose_code:
        body["purposeCode"] = purpose_code
    r = ctx.http.post(f"{base(ctx)}/{customer.id}/delegation-grants", bearer=bearer, json_body=body)
    if r.status == 201:
        # Only the customer can withdraw a grant (``/ciam/**`` accepts customer tokens only). At cleanup the customer
        # is suspended, which makes every grant of theirs unusable; the grant row itself stays as evidence.
        ctx.registry.add("delegation grant", r.json()["id"], None,
                         "customer-only withdrawal; unusable once the customer is suspended at cleanup")
    return r


def withdraw(ctx: Context, bearer: Secret, customer: Customer, grant_id: str, reason: str) -> Response:
    return ctx.http.post(f"{base(ctx)}/{customer.id}/delegation-grants/{grant_id}/revoke", bearer=bearer,
                         json_body={"reason": reason})


def purpose(ctx: Context, op: Secret, workload_id: str, code: str, scopes: list[str], max_seconds: int) -> dict:
    r = ctx.http.post(f"{ctx.admin_base()}/ciam/agent-workloads/{workload_id}/purposes", bearer=op, json_body={
        "purposeCode": code, "description": "cookbook purpose", "scopes": scopes,
        "maxValiditySeconds": max_seconds}).expect(201).json()
    ctx.registry.add("consent purpose", r.get("id", code), lambda: ctx.http.post(
        f"{ctx.admin_base()}/ciam/agent-workloads/{workload_id}/purposes/{r['id']}/retire", bearer=ctx.operator()),
        "retire")
    return r
