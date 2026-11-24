---
stage: none
group: Embody
info: This page is owned by <https://handbook.gitlab.com/handbook/engineering/embody-team/>
description: Monitor application performance and troubleshoot performance issues.
ignore_in_report: true
title: Set up Observability on GitLab Self-Managed
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab Self-Managed
- Status: Beta

{{< /details >}}

Observability data is collected in a separate application outside of your GitLab.com instance.
Problems with your GitLab instance do not impact collecting or viewing your observability data and vice-versa.

For GitLab Self-Managed, you control where data is stored.

## Workflow

To set up Observability on your GitLab Self-Managed instance, you will:

1. Ensure you meet the prerequisites.
1. Provision a server and storage.
1. Configure Docker and install Observability in a container.
1. Configure network access.
1. Configure the URL for your group in the Admin area, or for your personal namespace by using the Rails console.

## Prerequisites

- You must have an EC2 instance or similar virtual machine with:
  - Minimum: `t3.large` (2 vCPU, 8 GB RAM).
  - Recommended: `t3.xlarge` (4 vCPU, 16 GB RAM) for production use.
  - At least 100 GB storage space.
- Docker and Docker Compose must be installed.
- Your GitLab version must be 18.1 or later.
- Your GitLab instance must be connected to the Observability instance.

### Provision server and storage

For AWS EC2:

1. Launch an EC2 instance with at least 2 vCPU and 8 GB RAM.
1. Add an EBS volume of at least 100 GB.
1. Connect to your instance using SSH.

#### Mount storage volume

```shell
sudo mkdir -p /mnt/data
sudo mount /dev/xvdbb /mnt/data  # Replace xvdbb with your volume name
sudo chown -R $(whoami):$(whoami) /mnt/data
```

For permanent mounting, add to `/etc/fstab`:

```shell
echo '/dev/xvdbb /mnt/data ext4 defaults,nofail 0 2' | sudo tee -a /etc/fstab
```

### Install Docker

For Ubuntu/Debian:

```shell
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $(whoami)
```

For Amazon Linux:

```shell
sudo dnf update
sudo dnf install -y docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $(whoami)
```

Sign out and back in, or run:

```shell
newgrp docker
```

#### Configure Docker to use the mounted volume

```shell
sudo mkdir -p /mnt/data/docker
sudo bash -c 'cat > /etc/docker/daemon.json << EOF
{
  "data-root": "/mnt/data/docker"
}
EOF'
sudo systemctl restart docker
```

Verify with:

```shell
docker info | grep "Docker Root Dir"
```

#### Install GitLab Observability

```shell
cd /mnt/data
git clone -b main https://gitlab.com/gitlab-org/embody-team/experimental-observability/gitlab_o11y.git
cd gitlab_o11y/deploy/docker
docker-compose up -d
```

If you encounter timeout errors, use:

```shell
COMPOSE_HTTP_TIMEOUT=300 docker-compose up -d
```

#### Optional: Use an external ClickHouse database

If you'd prefer, you can use your own ClickHouse database.

Prerequisites:

- Ensure your external ClickHouse instance is accessible and properly configured with
  any required authentication credentials.

Before you run `docker-compose up -d`, complete the following steps:

1. Open `docker-compose.yml` file.
1. Comment out:
   - The `clickhouse` and `zookeeper` services.
   - The `x-clickhouse-defaults` and `x-clickhouse-depend` sections.
1. Replace all occurrences of `clickhouse:9000` with your relevant ClickHouse endpoint and TCP port (for example, `my-clickhouse.example.com:9000`) in the following files. If your ClickHouse instance requires authentication, you may also need to update connection strings to include credentials:
   - `docker-compose.yml`
   - `otel-collector-config.yaml`
   - `prometheus-config.yml`

### Configure network access for GitLab Observability

To properly receive telemetry data, you need to open specific ports in your GitLab Observability instance's security group:

1. Go to **AWS Console** > **EC2** > **Security Groups**.
1. Select the security group attached to your GitLab Observability instance.
1. Select **Edit inbound rules**.
1. Add the following rules:
   - Type: Custom TCP, Port: 8080, Source: Your IP or 0.0.0.0/0 (for UI access)
   - Type: Custom TCP, Port: 4317, Source: Your IP or 0.0.0.0/0 (for OTLP gRPC)
   - Type: Custom TCP, Port: 4318, Source: Your IP or 0.0.0.0/0 (for OTLP HTTP)
   - Type: Custom TCP, Port: 9411, Source: Your IP or 0.0.0.0/0 (for Zipkin - optional)
   - Type: Custom TCP, Port: 14268, Source: Your IP or 0.0.0.0/0 (for Jaeger HTTP - optional)
   - Type: Custom TCP, Port: 14250, Source: Your IP or 0.0.0.0/0 (for Jaeger gRPC - optional)
1. Select **Save rules**.

Now access the GitLab Observability UI at:

```plaintext
http://[your-instance-ip]:8080
```

### Configure TLS

The Docker Compose stack serves plain HTTP. GitLab requires HTTPS for both the service URL
and the OpenTelemetry endpoint, so put a reverse proxy with a TLS certificate in front of
the stack before you continue.

Terminate TLS for these two upstreams:

| Upstream | Container port | Purpose |
| -------- | -------------- | ------- |
| GitLab Observability UI and API | `8080` | The service URL that GitLab connects to |
| OpenTelemetry HTTP receiver | `4318` | The endpoint that receives exported telemetry |

GitLab connects to the OpenTelemetry receiver on port `14318` unless the OTel URL override
includes an explicit port.
A URL without a port, such as `https://otel.example.com`, resolves to port `14318` even
though the `https` scheme implies `443`.
To use any other port, including `443`, add it to the override, for example
`https://otel.example.com:443`.

An `http://` URL is saved without an error, but fails later when a user opens Observability
or when a pipeline exports telemetry.

### Configure the URL for your group or personal namespace

Configure the GitLab Observability URL for a group in the Admin area, or for a personal
namespace by using the Rails console.

{{< tabs >}}

{{< tab title="Group" >}}

Prerequisites:

- You must have administrator access to your GitLab instance.
- You must have TLS endpoints for your GitLab Observability instance.
- You must know the namespace ID of the group. To find the ID, go to the group and
  select **Settings** > **General**.

1. In the upper-right corner, select **Admin**.
1. In the left sidebar, select **Observability**.
1. Select **New O11y service setting**.
1. Complete the fields:
   - **Namespace ID**: The ID of the group to configure.
   - **Service URL**: The HTTPS URL of your GitLab Observability instance, for example
     `https://o11y.example.com`.
   - **User email** and **Password**: The credentials used to authenticate with your
     GitLab Observability instance.
   - **Encryption key**: A secure string of at least 32 characters.
   - **OTel URL override**: The HTTPS OpenTelemetry endpoint of your instance, for example
     `https://o11y.example.com:14318`.
1. Select **Save changes**.

Set **OTel URL override**.
On GitLab Self-Managed, the default value is derived from a GitLab.com service name and does
not point to your instance.
If you leave the field blank, telemetry is sent to an endpoint that does not exist, and no
error is shown.

Leave **MCP URL override** blank.
The Model Context Protocol server is available on GitLab.com only.
For more information, see [Observability MCP server](mcp_server.md).

After you save, GitLab returns to the **New O11y service setting** page so that you can add a
configuration for another group.
To view or change an existing configuration, in the left sidebar, select **Observability**,
then select **Edit** for that namespace.

The **Service name** column on the **O11y service settings** page shows a value derived from
the service URL, not the URL itself.

{{< /tab >}}

{{< tab title="Personal namespace" >}}

GitLab Self-Managed has no UI path for enabling Observability for a personal namespace.
Configure the setting directly through the Rails console.

1. Access the Rails console:

   ```shell
   docker exec -it gitlab gitlab-rails console
   ```

1. Configure the observability settings for the personal namespace:

   ```ruby
   namespace = User.find_by_username('your-username').namespace

   Observability::GroupO11ySetting.create!(
     group_id: namespace.id,
     o11y_service_url: 'your-o11y-instance-url',
     o11y_service_user_email: 'your-email@example.com',
     o11y_service_password: 'your-secure-password',
     o11y_service_post_message_encryption_key: 'your-super-secret-encryption-key-here-32-chars-minimum',
     o11y_otel_url: 'your-otel-endpoint'
   )
   ```

   Replace:
   - `your-username` with the username that owns the personal namespace.
   - `your-o11y-instance-url` with the HTTPS URL of your GitLab Observability instance (for example: `https://o11y.example.com`).
   - Email and password with your preferred credentials.
   - Encryption key with a secure 32+ character string.
   - `your-otel-endpoint` with the HTTPS OpenTelemetry endpoint of your instance (for example: `https://o11y.example.com:14318`).

Set `o11y_otel_url`.
When this value is not set, it defaults to an endpoint derived from a GitLab.com service
name, which does not point to your instance.
Telemetry sent to that endpoint is lost, and no error is shown.

The `group_id` column stores the namespace ID for both groups and personal namespaces.

{{< /tab >}}

{{< /tabs >}}

## Next steps

- [Send your telemetry data to GitLab Observability](send.md).
- [Show CI/CD pipeline telemetry](ci_cd.md).
- [Get troubleshooting information](troubleshooting.md).
