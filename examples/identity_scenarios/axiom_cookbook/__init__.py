"""Axiom identity cookbook: small, readable helpers over Axiom's public HTTP interface.

Nothing here knows about Agents, Use Cases, Gateways or business actions. The helpers speak OAuth 2.0 / OIDC and
Axiom's administrative REST API, and keep three identities apart at all times: the authenticated OAuth client, the
represented person or customer (``sub``), and the acting workload (``act``).
"""
