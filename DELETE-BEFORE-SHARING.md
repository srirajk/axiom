# Delete before sharing

Use this checklist only on a copied export of the repository. Do not delete these paths from the
working repository or its Git branch.

## 1. Remove assistant, session, and internal handoff material

- `.claude/`
- `.codex/`
- `.wolf/`
- `AGENTS.md`
- `CLAUDE.md`
- `codex-handshake/`

Axiom does not require these paths at runtime. If the recipient needs only the operating product,
also remove `docs/history/`, which contains historical Probata integration provenance rather than
current Axiom operating instructions.

## 2. Remove credentials and local state

- `.env`
- any populated environment file outside committed `*.example` templates
- local certificates, tokens, exported cookies, signing keys, database dumps, and volume exports

Keep `.env.example` and `admin/.env.example`. The recipient must generate a new
`AXIOM_SECRETS_MASTER_KEY` and choose new database and administrator passwords.

## 3. Remove local tools, caches, and generated output

- `.git/`, only when sharing an archive instead of a Git repository
- `.idea/`
- `.vscode/`
- `server/target/`
- `admin/node_modules/`
- `admin/dist/`
- `seed/.venv/`
- every `__pycache__/` directory
- every `test-results/`, `playwright-report/`, and `coverage/` directory
- every `.DS_Store`, `*.pyc`, and local log file

## 4. Keep the operating product

Do not delete these paths:

- `README.md`
- `DELETE-BEFORE-SHARING.md`
- `.env.example`
- `compose.yaml`
- `server/`
- `admin/`
- `platform-contract/`
- `platform-policy/`
- `scripts/`
- `seed/`

## 5. Final checks on the copied export

Confirm that `.env`, `.claude/`, `.codex/`, `.wolf/`, local signing keys, database dumps, and build
outputs are absent. Then configure and verify the copied package:

```bash
cp .env.example .env
chmod 600 .env
openssl rand -base64 32
# Put recipient-owned values in .env.
docker compose up -d --build
docker compose ps --all
curl --fail http://localhost:8180/actuator/health
curl --fail http://localhost:8180/.well-known/openid-configuration
```

The `bootstrap` container must exit with status `0`. The long-running services must be healthy. Sign
in to `http://localhost:5182` with the recipient's administrator credential before handing over the
package.

If Probata is part of the handoff, prepare it as a separate repository. Probata owns its Axiom
application, OAuth clients, roles, memberships, and scoped attributes, and reconciles them through
Axiom's public administrative APIs. Do not pre-populate those records with raw database writes.
