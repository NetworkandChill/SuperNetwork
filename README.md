# Super Network — N&C Club CRM (source code only)

**Confidential data is intentionally excluded** from this repository. This is a deployable source scaffold, **not a completed production rollout**. The private source CRM contacts remain in a separate SQLite archive and need a reviewed, secure migration procedure before use by a team.

## Contents
- `server.py` — original internal Python CRM API, adapted for Railway port and TLS-proxied deployment.
- `web/` — internal CRM frontend assets.
- `schema_empty.sql` — database structure and non-sensitive membership settings only; contains **no contacts, team credentials, notes or personal records**.
- `Dockerfile`, `railway.json` — Railway hosting configuration.
- `.gitignore`, `.dockerignore` — prevent accidental inclusion of SQLite databases, CSVs, XLSX files, backups and `.env` credentials.

## Railway setup (requires access to source repository)
1. Connect the source repository to the **Super Network** Railway project.
2. Create a **persistent volume** mounted at `/data`. Never use ephemeral storage for CRM data.
3. Configure `NC_ADMIN_PASSWORD` in Railway as a strong random secret (minimum 14 characters). Use separate deployment credentials; do not commit them.
4. Use a Railway HTTPS domain and confirm the application's session cookies carry `Secure`, `HttpOnly`, `SameSite=Strict`.
5. Review security posture, user permissions, data residency, backups, and UK GDPR requirements **before** inviting sales users.
6. Import the existing database to the volume using a vetted, authenticated and audited data migration. Do **not** commit the SQLite archive, Excel files or exports to GitHub, nor upload the archive to a public web endpoint.

## Known limitations
- The Docker container will launch with an empty CRM if no volume is populated, not with the 31,596-contact database. Existing contact data must be migrated separately.
- SQLite on a single writable volume is acceptable only for a limited, controlled pilot; it is not a substitute for the planned PostgreSQL-backed, production multi-user system.
- No SSO/MFA, persistent sessions across replicas, independent security testing or full privacy-compliance verification.
- Only deploy privately for an authorised staging review until these gaps are addressed.

## Original data files (never commit)
The previously supplied `NC_Club_CRM_Working_Local_Application.zip` contains confidential contacts; handle it as a separate protected data artifact. Use the original `nc_club.sqlite3` on a secure, controlled migration path and retain the original backup offline.