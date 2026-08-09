# UNDER CONSTRUCTION

# Axiom

Axiom is a standalone identity and platform authorization service for enterprise applications. It
provides workforce identity, OAuth 2.0 and OpenID Connect, application-scoped access control,
separation of duties, and policy-backed authorization.

This repository is under active construction. The local Compose environment is suitable for
development, integration, and product evaluation. It is not yet certified for production use.

## Characteristics

- One deployment serves one customer organization and may serve multiple applications.
- PostgreSQL is the system of record for identities, applications, access assignments, and policy
  lifecycle data.
- Redis stores short-lived OAuth state and authorization artifacts.
- Cerbos evaluates Axiom platform authorization policies.
- The authorization server issues signed OpenID Connect tokens and publishes discovery metadata and
  JSON Web Keys.
- Browser clients use Authorization Code with PKCE.
- Service clients use confidential client credentials.
- The administrative application manages identities, groups, applications, clients, memberships,
  roles, and policies.
- Bootstrap and reference directory seeding are idempotent and use supported service or API paths.
- Consumer applications own their application-specific roles, memberships, and domain data. Axiom
  does not own Probata governance policy, evidence, or contextual clearance.

## Repository structure

```text
admin/              Axiom administrative web application
platform-contract/  Platform authorization contract
platform-policy/    Cerbos platform policy package
scripts/            Focused operational verification utilities
seed/               Optional Axiom-owned reference directory seed
server/             Spring authorization server and administrative APIs
compose.yaml        Standalone local environment
```

## Prerequisites

- Docker Desktop with Docker Compose
- At least 4 GB of memory available to Docker
- `curl` for health verification
- Python 3.12 or later and `uv` only when applying the optional reference directory seed

The default local ports are:

| Service | URL or port |
|---|---|
| Axiom issuer and API | `http://localhost:8180` |
| Axiom Admin | `http://localhost:5182` |
| PostgreSQL | `localhost:5434` |
| Redis | `localhost:6381` |
| Cerbos HTTP | `http://localhost:3692` |
| Cerbos gRPC | `localhost:3693` |

## Configure the local environment

Create the local environment file:

```bash
cp .env.example .env
```

Set the following values in `.env` before starting Axiom:

- `AXIOM_DB_PASSWORD`
- `AXIOM_ADMIN_PASSWORD`
- `AXIOM_SECRETS_MASTER_KEY`

Generate a suitable local master key with:

```bash
openssl rand -base64 32
```

The remaining values in `.env.example` provide local defaults and configurable host ports. Optional
Policy Studio model credentials may remain empty. Axiom remains operational without them.

Never commit `.env` or real credentials.

## Start Axiom

From the repository root:

```bash
docker compose up -d --build
```

Compose performs the following sequence:

1. Starts PostgreSQL, Redis, and Cerbos.
2. Runs Flyway database migrations.
3. Runs the one-shot Axiom bootstrap.
4. Creates the configured organization, administrator, signing identity, and baseline platform
   policy when missing.
5. Starts the Axiom authorization server.
6. Starts the Axiom Admin application.

The `bootstrap` container should exit with status `0`. The remaining services should report healthy.

## Verify the environment

Check the containers:

```bash
docker compose ps --all
```

Check Axiom health:

```bash
curl --fail http://localhost:8180/actuator/health
```

Check OpenID Connect discovery:

```bash
curl --fail http://localhost:8180/.well-known/openid-configuration
```

Open the administrative application:

```text
http://localhost:5182
```

Sign in with username `admin` and the value configured as `AXIOM_ADMIN_PASSWORD`.

## Apply the optional reference directory

The bootstrap creates the organization and administrator. The optional reference seed creates
Axiom-owned workforce identities, groups, lifecycle examples, and group memberships through public
APIs. It does not create application-specific roles or business data.

```bash
set -a
source .env
set +a
uv run --project seed python seed/seed_meridian.py
```

The command is idempotent. A second execution reports the existing users, groups, and memberships as
unchanged rather than creating duplicates.

## Register consumer applications

Each consumer application owns its Axiom application record, OAuth clients, application roles,
memberships, and scoped attributes. Those records must be registered idempotently through Axiom's
public administrative APIs.

Probata-specific registration is intentionally owned by the Probata repository. Axiom can start and
operate without Probata, and Probata can reconcile its application access model against an existing
Axiom deployment without resetting Axiom.

## Stop and restart

Stop Axiom while preserving all data:

```bash
docker compose down --remove-orphans
```

Start it again with the existing volumes:

```bash
docker compose up -d
```

## Bare-metal local reset

The following operation permanently deletes the local Axiom database, identities, signing key,
Redis state, runtime policies, and audit volume. Docker images are preserved.

```bash
docker compose down -v --remove-orphans
docker compose up -d --build
```

Reapply the optional reference directory seed after the rebuilt services become healthy.

## Logs and troubleshooting

Follow the authorization server logs:

```bash
docker compose logs -f axiom
```

Inspect bootstrap output:

```bash
docker compose logs bootstrap
```

Inspect all service status and recent logs:

```bash
docker compose ps --all
docker compose logs --tail 200
```

If a configured host port is already in use, change the corresponding value in `.env` before
starting the stack.

## Data ownership

The local environment uses the following named volumes:

| Volume | Contents |
|---|---|
| `postgres-data` | Axiom system-of-record data |
| `redis-data` | Short-lived OAuth and session state |
| `signing-key` | Token signing identity |
| `cerbos-runtime` | Published runtime policy material |
| `cerbos-audit` | Cerbos audit output |

Do not delete these volumes during an ordinary restart. Use the bare-metal reset only when complete
local data destruction is intended.
