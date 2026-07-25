"""Meridian's application-neutral workforce directory fixture."""

from __future__ import annotations

from typing import Final, TypedDict


class GroupSpec(TypedDict):
    key: str
    name: str
    description: str


class UserSpec(TypedDict):
    id: str
    username: str
    email: str
    display_name: str
    department: str
    groups: list[str]
    lifecycle: str


GROUPS: Final[list[GroupSpec]] = [
    {"key": "platform-admins", "name": "Platform Administrators", "description": "Meridian platform administration"},
    {"key": "identity-operations", "name": "Identity Operations", "description": "Workforce identity and directory operations"},
    {"key": "banking-builders", "name": "Banking AI Builders", "description": "Banking engineering and data science"},
    {"key": "banking-governance", "name": "Banking Governance", "description": "Banking risk and governance stewardship"},
    {"key": "wealth-builders", "name": "Wealth AI Builders", "description": "Wealth engineering and data science"},
    {"key": "wealth-governance", "name": "Wealth Governance", "description": "Wealth risk and governance stewardship"},
    {"key": "financial-crime", "name": "Financial Crime Operations", "description": "AML, KYC and sanctions operations"},
    {"key": "enterprise-risk", "name": "Enterprise Risk", "description": "Independent enterprise risk oversight"},
    {"key": "internal-audit", "name": "Internal Audit", "description": "Independent audit and assurance"},
    {"key": "executive-oversight", "name": "Executive Oversight", "description": "Executive read-only oversight"},
]


def user(
    number: int,
    username: str,
    display_name: str,
    department: str,
    groups: list[str],
    lifecycle: str = "active",
) -> UserSpec:
    return {
        "id": f"meridian-{number:04d}",
        "username": username,
        "email": f"{username}@meridian.example",
        "display_name": display_name,
        "department": department,
        "groups": groups,
        "lifecycle": lifecycle,
    }


USERS: Final[list[UserSpec]] = [
    user(1001, "maya.chen", "Maya Chen", "Identity Operations", ["identity-operations"]),
    user(1002, "noah.williams", "Noah Williams", "Identity Operations", ["identity-operations"]),
    user(1003, "amina.yusuf", "Amina Yusuf", "Identity Operations", ["identity-operations"]),
    user(1004, "lucas.martin", "Lucas Martin", "Enterprise Platforms", ["platform-admins"]),
    user(1005, "elena.garcia", "Elena Garcia", "Enterprise Platforms", ["platform-admins"]),
    user(1006, "priyanka.rao", "Priyanka Rao", "Banking Technology", ["banking-builders"]),
    user(1007, "daniel.kim", "Daniel Kim", "Banking Governance", ["banking-governance"]),
    user(1008, "wei.liu", "Wei Liu", "Banking Data Science", ["banking-builders"]),
    user(1009, "riya.patel", "Riya Patel", "Banking Product", ["banking-builders"]),
    user(1010, "omar.hassan", "Omar Hassan", "Banking Risk", ["banking-governance"]),
    user(1011, "sofia.rossi", "Sofia Rossi", "Banking Technology", ["banking-builders"]),
    user(1012, "marcus.johnson", "Marcus Johnson", "Banking Data Science", ["banking-builders"]),
    user(1013, "hannah.lee", "Hannah Lee", "Banking Compliance", ["banking-governance"]),
    user(1014, "ethan.brown", "Ethan Brown", "Banking Engineering", ["banking-builders"]),
    user(1015, "chloe.dubois", "Chloe Dubois", "Banking Product", ["banking-builders"]),
    user(1016, "arjun.mehta", "Arjun Mehta", "Banking Data Science", ["banking-builders"]),
    user(1017, "nia.thompson", "Nia Thompson", "Banking Governance", ["banking-governance"]),
    user(1018, "samuel.green", "Samuel Green", "Banking Engineering", ["banking-builders"]),
    user(1019, "priya.nair", "Priya Nair", "Wealth Governance", ["wealth-governance"]),
    user(1020, "aisha.rahman", "Aisha Rahman", "Wealth Technology", ["wealth-builders"]),
    user(1021, "liam.oconnor", "Liam O'Connor", "Wealth Data Science", ["wealth-builders"]),
    user(1022, "grace.wang", "Grace Wang", "Wealth Risk", ["wealth-governance"]),
    user(1023, "isabella.moore", "Isabella Moore", "Wealth Product", ["wealth-builders"]),
    user(1024, "jacob.wilson", "Jacob Wilson", "Wealth Engineering", ["wealth-builders"]),
    user(1025, "fatima.khan", "Fatima Khan", "Wealth Compliance", ["wealth-governance"]),
    user(1026, "theo.anderson", "Theo Anderson", "Wealth Technology", ["wealth-builders"]),
    user(1027, "ava.martinez", "Ava Martinez", "Wealth Data Science", ["wealth-builders"]),
    user(1028, "sarah.okafor", "Sarah Okafor", "Financial Crime", ["financial-crime"]),
    user(1029, "mateo.silva", "Mateo Silva", "AML Operations", ["financial-crime"]),
    user(1030, "leila.haddad", "Leila Haddad", "Sanctions Operations", ["financial-crime"]),
    user(1031, "ben.carter", "Ben Carter", "KYC Operations", ["financial-crime"]),
    user(1032, "yasmin.ali", "Yasmin Ali", "Financial Crime Analytics", ["financial-crime"]),
    user(1033, "henry.clark", "Henry Clark", "AML Technology", ["financial-crime"]),
    user(1034, "james.walker", "James Walker", "Enterprise Risk", ["enterprise-risk"]),
    user(1035, "noor.siddiqui", "Noor Siddiqui", "Model Risk", ["enterprise-risk"]),
    user(1036, "evelyn.brooks", "Evelyn Brooks", "Executive Office", ["executive-oversight"]),
    user(1037, "morgan.reed", "Morgan Reed", "Risk Assurance", ["enterprise-risk", "internal-audit"]),
    user(1038, "keiko.tanaka", "Keiko Tanaka", "Internal Audit", ["internal-audit"]),
    user(1039, "victor.nguyen", "Victor Nguyen", "Internal Audit", ["internal-audit"]),
    user(1040, "gabriela.santos", "Gabriela Santos", "Enterprise Risk", ["enterprise-risk"]),
    user(1041, "zainab.bello", "Zainab Bello", "Financial Crime Risk", ["financial-crime", "enterprise-risk"]),
    user(1042, "alex.novak", "Alex Novak", "Enterprise Platforms", ["platform-admins"]),
    user(1043, "ingrid.larsen", "Ingrid Larsen", "Identity Operations", ["identity-operations"]),
    user(1044, "rahul.verma", "Rahul Verma", "AI Enablement", ["banking-builders", "wealth-builders"]),
    user(1045, "mei.lin", "Mei Lin", "Wealth Engineering", ["wealth-builders"]),
    user(1046, "david.mensah", "David Mensah", "Financial Crime Analytics", ["financial-crime"]),
    user(1047, "laura.stein", "Laura Stein", "Internal Audit", ["internal-audit"], "invited"),
    user(1048, "christopher.young", "Christopher Young", "Executive Office", ["executive-oversight"], "deactivated"),
]
