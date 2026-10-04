"""A small, generic exchange topology used by the token-exchange examples. Nothing in it is consumer-specific:

* ``portal`` — an application with a browser client (people sign in here) and a service client registered as the
  workload ``portal-svc``; Axiom's on-behalf-of profile lets a workload act for a person signed in to *its own*
  application only;
* ``reports-svc`` — a second, unrelated workload in its own application;
* ``edge`` — an exchange intermediary (a registered broker client) with its own audience;
* ``orders-api`` — a protected resource (an application audience) with a receiver client that introspects;
* exact edges: portal-svc → edge (intermediary), portal-svc → orders-api (resource, via the intermediary),
  portal-svc → reports-svc (workload-to-workload, via the intermediary), reports-svc → edge.

Registration alone grants nothing: every hop needs an explicit edge, and every token is re-checked live.
"""
from __future__ import annotations

from dataclasses import dataclass

from .context import Context
from .oauth import Client
from .redaction import Secret

READ, WRITE = "orders.read", "orders.write"


@dataclass
class Topology:
    portal_app: dict
    web: Client
    portal_svc: Client
    portal_workload: dict
    reports_app: dict
    reports_svc: Client
    reports_workload: dict
    edge: Client
    edge_audience: str
    orders_app: dict
    orders_receiver: Client
    member: str
    member_password: Secret
    outsider: str
    outsider_password: Secret
    reader_role: dict


def build(ctx: Context, op: Secret) -> Topology:
    portal = ctx.application(op, "portal")
    web, _ = ctx.public_client(op, portal, "portal-web", [READ, WRITE])
    portal_svc, _ = ctx.service_client(op, portal, "portal-svc", [READ, WRITE])
    portal_wl = ctx.workload(op, portal_svc, "portal-svc")
    reports = ctx.application(op, "reports")
    reports_svc, _ = ctx.service_client(op, reports, "reports-svc", [READ, WRITE])
    reports_wl = ctx.workload(op, reports_svc, "reports-svc")
    edge_app = ctx.application(op, "edge")
    edge, _ = ctx.service_client(op, edge_app, "edge", [READ, WRITE])
    ctx.broker(op, edge, edge_app["audience"], [READ, WRITE])
    orders = ctx.application(op, "orders-api")
    receiver, _ = ctx.service_client(op, orders, "orders-receiver", [READ])
    ctx.route(op, portal_wl["id"], "GATEWAY", edge_app["audience"], [READ, WRITE])
    ctx.route(op, portal_wl["id"], "RESOURCE", orders["audience"], [READ])
    ctx.route(op, portal_wl["id"], "AGENT", reports["audience"], [READ], destination_workload=reports_wl["id"])
    ctx.route(op, reports_wl["id"], "GATEWAY", edge_app["audience"], [READ])
    reader = ctx.app_role(op, portal, "reader", {READ: "allow"})
    member, password = ctx.workforce_user(op, "member")
    ctx.membership(op, portal, member, reader["id"])
    outsider, outsider_password = ctx.workforce_user(op, "outsider")
    return Topology(portal, web, portal_svc, portal_wl, reports, reports_svc, reports_wl, edge, edge_app["audience"],
                    orders, receiver, member, password, outsider, outsider_password, reader)
