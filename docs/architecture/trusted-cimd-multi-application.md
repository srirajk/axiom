# Trusted CIMD clients across applications

A tenant may approve one external client URL for several workforce applications. The first approval creates one internal `cimd-...` client. Later approvals in the same tenant reuse that ID and add an application-specific scope ceiling. The client authentication method, redirect URIs, population and refresh setting are shared settings; a conflicting second approval is refused. Existing duplicate internal clients remain readable, but must be reseeded before adding further applications to that URL. Customer sign-in remains one application per internal client because its durable consent record is keyed by that client ID.

Use the existing tenant admin API:

- `POST /admin/tenants/{tenant}/applications/{applicationId}/trusted-clients` adds the first or another application approval. The response contains `internalClientId` and an `applications` map of application IDs to approved scopes.
- `GET /admin/tenants/{tenant}/applications/{applicationId}/trusted-clients` lists clients approved for that application, including clients whose primary row belongs to another application.
- `DELETE /admin/tenants/{tenant}/applications/{applicationId}/trusted-clients/{id}?expectedRevision=...` removes only that application's approval. The next response from GET supplies the current revision.

At authorization, `resource` must select exactly one active approved application by audience or registered HTTPS resource URI. The selected application determines the issued audience, allowed scopes and workforce membership. The authorization code and refresh family retain that application choice; a later `resource` cannot switch it. Removing an approval ends its sessions and revokes the native workload's Gateway route for that application's audience. The workload remains active while another approval uses it; removing the final approval retires it and revokes its remaining routes.

Flyway V48 adds `trusted_application_scopes` and fills it for existing trusted clients. It does not delete records. Roll the new server image with this migration; no database reset is needed. The existing external-URL to internal-client lookup still resolves the one native workload by the signed token's tenant and audience.
