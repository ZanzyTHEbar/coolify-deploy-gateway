# Coolify Deploy Gateway

Small Go ingress for signed GitHub deployment webhooks. It exposes one route and calls Coolify's authenticated deploy API over the private LAN.

## Contract

```text
POST /webhooks/source/github/manual?uuid=<allowlisted-uuid>&force=false
```

The request must be a signed GitHub `push` for the repository and branch configured for that UUID. `ping` is accepted without deploying. All other paths and methods are rejected.

## Configuration

Set these as Coolify runtime environment variables, never in Git. Use a private Coolify origin; plain HTTP requires an explicit opt-in and is only for a trusted private network.

```json
{
  "COOLIFY_BASE_URL": "<private-coolify-origin>",
  "COOLIFY_ALLOW_INSECURE_HTTP": "true",
  "COOLIFY_API_TOKEN": "<deploy-only-token>",
  "DEPLOY_TARGETS_JSON": "{\"<resource-uuid>\":{\"secret\":\"<github-webhook-secret>\",\"repository\":\"owner/repository\",\"ref\":\"refs/heads/main\"}}"
}
```

Use a Coolify API token with `deploy` permission only. The HTTP opt-in is required because the current private Coolify endpoint presents the Traefik default certificate; replace it with trusted internal TLS before removing the opt-in.

## Deployment

Create a separate Coolify Docker Compose application from this repository. Use Compose location `/docker-compose.yaml`, expose no host port, configure no Coolify domain, and attach the existing private network shared with Newt so it can resolve `coolify-deploy-gateway:8080`.

Enable Coolify API access and allow only the source address observed for this gateway's private-network requests. Verify the source in Coolify logs before setting the allowlist; never allow the public ingress address. Use one unique high-entropy webhook secret per target. Payloads are capped at 1 MiB. The in-process replay window is ten minutes; keep one gateway replica and treat deployment delivery as at-least-once across restarts.

Configure Pangolin/Newt to route only `deploy.zacariahheim.com` and the path `/webhooks/source/github/manual` to `http://coolify-deploy-gateway:8080` without stripping the path. GitHub's payload URL is:

```text
https://deploy.zacariahheim.com/webhooks/source/github/manual?uuid=<resource-uuid>&force=false
```
