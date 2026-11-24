---
stage: Analytics
group: Analytics Instrumentation
info: Any user with at least the Maintainer role can merge updates to this content. For details, see <https://docs.gitlab.com/development/development_processes/#development-guidelines-review>.
title: Service Ping internal API
---

The Service Ping internal API is used by services that report Service Ping on behalf of a GitLab instance,
such as the Service Ping exporter.
The API cannot be used by other consumers.
This documentation is intended for people working on the GitLab codebase.

## Authentication

Requests require Workhorse internal API authentication and a Service Ping JSON Web Token (JWT).

To create the JWT, clients:

1. Read the Service Ping secret.
   The secret is in the file set by `service_ping.secret_file` in `gitlab.yml`,
   by default `.gitlab_service_ping_secret` in the GitLab Rails root.
   The file contains a Base64-encoded 32-byte value, and must be the same on every Rails node.
   How the file is created depends on the installation method:
   - Linux package installations: `gitlab-ctl reconfigure` creates the file.
     The value comes from `gitlab_rails['service_ping_secret']` in `gitlab.rb` if set,
     otherwise it is generated and stored in `/etc/gitlab/gitlab-secrets.json`.
   - Helm chart installations: the chart generates a Kubernetes Secret, or uses one you provide,
     and mounts it into the Rails pods.
   - Other installations, such as self-compiled installations and the GDK: GitLab creates the file
     at startup if it does not exist.
     If the Rails root is not writable, GitLab logs a warning and
     requests to the API fail with `401 Unauthorized` until the file exists.
1. Sign a JWT with the secret and the `HS256` algorithm, with these claims:
   - `iss`: `gitlab-service-ping`
   - `aud`: `gitlab`
   - `sub`: The name of the calling service, for example `service-ping-exporter`.
   - `iat`: The current time. GitLab rejects tokens issued more than five minutes ago.
1. Pass the JWT in the `Gitlab-Service-Ping-Api-Request` header.

## Internal endpoints

### Fetch the instance identity and Service Ping settings

Use a GET request to retrieve the identity of the instance and its Service Ping settings.

```plaintext
GET /internal/service_ping/instance
```

Example request:

```shell
curl --header "Gitlab-Service-Ping-Api-Request: <json-web-token>" "https://gitlab.example.com/api/v4/internal/service_ping/instance"
```

Example response:

```json
{
  "identity": {
    "instance_id": "d4f5e6a7-1b2c-4d3e-8f9a-0b1c2d3e4f5a",
    "unique_instance_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "host_name": "gitlab.example.com",
    "instance_version": "18.6.0-ee"
  },
  "settings": {
    "service_ping_enabled": true,
    "service_ping_generation_enabled": true,
    "service_ping_optional_metrics_enabled": true
  }
}
```

`service_ping_enabled` reports whether the instance is allowed to send Service Ping,
including when the license requires Service Ping.
Rails sends Service Ping only when `service_ping_generation_enabled` is also `true`.
Fields are only added, never renamed or removed, so older clients keep working.
