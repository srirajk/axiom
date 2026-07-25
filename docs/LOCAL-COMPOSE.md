# Local Compose

## Start

```bash
cp .env.example .env
docker compose up -d --build
```

The one-shot `bootstrap` service creates the empty Meridian organization, platform administrator,
signing identity and initial tenant policy through Axiom services. Flyway creates database structure
only. Reference directory data is applied separately by the idempotent seed command.

## Host endpoints

| Endpoint | Default |
|---|---|
| Axiom issuer and API | `http://localhost:8180` |
| Axiom Admin | `http://localhost:5182` |
| PostgreSQL | `localhost:5434` |
| Redis | `localhost:6381` |
| Platform Cerbos HTTP | `http://localhost:3692` |
| Platform Cerbos gRPC | `localhost:3693` |

All ports are configurable in `.env`. Publishing PostgreSQL, Redis and Cerbos is a local-integration
convenience requested for the Compose phase. The future Helm chart must default infrastructure
services to cluster-internal exposure.

## Current compatibility note

The first standalone snapshot still bootstraps the existing Probata OAuth clients in Java so the
current consumer remains usable. This is explicitly tracked AXP-0 debt. Probata becomes the owner of
its application/client provisioning after Axiom's persisted application scope catalogue is completed.

The platform Cerbos container also still reads the compatibility disk package. AXP-7 replaces it with
the PostgreSQL dynamic store and the audited Axiom publisher before production closure.
