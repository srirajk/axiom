# Standalone Extraction Status

**Snapshot date:** 2026-07-24  
**Source:** `/Users/srirajkadimisetty/projects/uac`

## Included

- Axiom Spring service source, migrations and focused tests.
- Axiom Admin source.
- Isolated Axiom platform-policy package.
- Accepted work order, OIDC contract and critic review.

## Deliberately retained with UAC

- Probata/UAC provisioning and reference-demo runners.
- The Probata platform-contract document and consumer-specific grounding adapter inputs.
- UAC Docker Compose integration and consumer smoke journeys.
- Generated Maven, npm and frontend build output.

## Known compatibility seams to remove under AXP-0

- compiled `probata-spa` and `probata-api` client bootstrap;
- Probata-specific service-tenant and audience fallback;
- Probata-only subject-context JWT validation branch;
- Probata-specific Policy Studio grounding provider; and
- consumer-specific names in server configuration and documentation.

These are tracked extraction inputs, not accepted standalone architecture.

## Cutover rule

UAC remains the compatibility source until:

1. this repository builds without UAC context;
2. an immutable standalone image is published;
3. Probata passes browser OIDC, service-token and live-context journeys against that image;
4. a second application passes the same generic integration profile; and
5. the consumer pins the verified image version or digest.
