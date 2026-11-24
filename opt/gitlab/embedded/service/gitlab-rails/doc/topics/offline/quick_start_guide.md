---
stage: Developer Experience
group: Application Lifecycle
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Install, configure, and use a GitLab Self-Managed instance in an environment with no internet access.
title: Install an offline GitLab Self-Managed instance
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab Self-Managed

{{< /details >}}

This is a step-by-step guide that helps you install, configure, and use a GitLab Self-Managed
instance entirely offline.

## Installation

> [!note]
> This guide assumes the server is Ubuntu 20.04 using the [Linux package installation method](../../install/package/_index.md) and is running GitLab Enterprise Edition. Instructions for other servers may vary.
> This guide also assumes the server host resolves as `my-host.internal`, which you should replace with your
> server's FQDN, and that you have access to a different server with Internet access to download the required package files.

<i class="fa-youtube-play" aria-hidden="true"></i>
For a video walkthrough of this process, see [Offline GitLab Installation: Downloading & Installing](https://www.youtube.com/watch?v=TJaq4ua2Prw).

### Download the GitLab package

You should [download the GitLab package](../../update/package/_index.md#upgrade-with-a-downloaded-package) and relevant dependencies using a server of the same operating system type that has access to the Internet.

If your offline environment has no local network access, you must manually transport the relevant package through physical media, such as a USB drive.

In Ubuntu, this can be performed on a server with Internet access using the following commands:

```shell
# Download the bash script to prepare the repository
curl --silent "https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.deb.sh" | sudo bash

# Download the gitlab-ee package and dependencies to /var/cache/apt/archives
sudo apt-get install --download-only gitlab-ee

# Copy the contents of the apt download folder to a mounted media device
sudo cp /var/cache/apt/archives/*.deb /path/to/mount
```

### Install the GitLab package

Prerequisites:

- Before installing the GitLab package on your offline environment, ensure that you have installed all required dependencies first.

If you are using Ubuntu, you can install the dependency `.deb` packages you copied across with `dpkg`. Do not install the GitLab package yet.

```shell
# Go to the physical media device
sudo cd /path/to/mount

# Install the dependency packages
sudo dpkg -i <package_name>.deb
```

[Use the relevant commands for your operating system to install the package](../../update/package/_index.md#upgrade-with-a-downloaded-package) but make sure to specify an `http`
URL for the `EXTERNAL_URL` installation step. Once installed, you can manually
configure the SSL yourself.

You should set up a domain for IP resolution rather than bind to the server's IP address.
A domain provides a stable target for the certificate's Common Name (CN) and simplifies the long-term
resolution.

The following example for Ubuntu specifies the `EXTERNAL_URL` using HTTP and installs the GitLab package:

```shell
sudo EXTERNAL_URL="http://my-host.internal" dpkg -i <gitlab_package_name>.deb
```

## Enabling SSL

Follow these steps to enable SSL for your fresh instance. These steps reflect those for
[manually configuring SSL in the NGINX configuration](https://docs.gitlab.com/omnibus/settings/ssl/#configure-https-manually):

1. Make the following changes to `/etc/gitlab/gitlab.rb`:

   ```ruby
   # Update external_url from "http" to "https"
   external_url "https://my-host.internal"

   # Set Let's Encrypt to false
   letsencrypt['enable'] = false
   ```

1. Create the following directories with the appropriate permissions for generating self-signed
   certificates:

   ```shell
   sudo mkdir -p /etc/gitlab/ssl
   sudo chmod 755 /etc/gitlab/ssl
   sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/gitlab/ssl/my-host.internal.key -out /etc/gitlab/ssl/my-host.internal.crt
   ```

1. Reconfigure your instance to apply the changes:

   ```shell
   sudo gitlab-ctl reconfigure
   ```

## Enabling the GitLab container registry

Follow these steps to enable the container registry. These steps reflect those for
[configuring the container registry under an existing domain](../../administration/packages/container_registry.md#configure-container-registry-under-an-existing-gitlab-domain):

1. Make the following changes to `/etc/gitlab/gitlab.rb`:

   ```ruby
   # Change external_registry_url to match external_url, but append the port 4567
   external_url "https://gitlab.example.com"
   registry_external_url "https://gitlab.example.com:4567"
   ```

1. Reconfigure your instance to apply the changes:

   ```shell
   sudo gitlab-ctl reconfigure
   ```

## Allow the Docker daemon to trust the registry and GitLab Runner

Provide your Docker daemon with your certs by
[following the steps for using trusted certificates with your registry](../../administration/packages/container_registry.md#configure-self-signed-certificates):

```shell
sudo mkdir -p /etc/docker/certs.d/my-host.internal:5000

sudo cp /etc/gitlab/ssl/my-host.internal.crt /etc/docker/certs.d/my-host.internal:5000/ca.crt
```

Provide your GitLab Runner (to be installed next) with your certs by
[following the steps for using trusted certificates with your runner](https://docs.gitlab.com/runner/install/docker/#installing-trusted-ssl-server-certificates):

```shell
sudo mkdir -p /etc/gitlab-runner/certs

sudo cp /etc/gitlab/ssl/my-host.internal.crt /etc/gitlab-runner/certs/ca.crt
```

## Enabling GitLab Runner

[Following a similar process to the steps for installing our GitLab Runner as a Docker service](https://docs.gitlab.com/runner/install/docker/#install-the-docker-image-and-start-the-container), you must first register your runner:

```shell
$ sudo docker run --rm -it -v /etc/gitlab-runner:/etc/gitlab-runner gitlab/gitlab-runner register
Updating CA certificates...
Runtime platform                                    arch=amd64 os=linux pid=7 revision=1b659122 version=12.8.0
Running in system-mode.

Enter the GitLab instance URL (for example, https://gitlab.com/):
https://my-host.internal
Enter the registration token:
XXXXXXXXXXX
Enter a description for the runner:
[eb18856e13c0]:
Enter tags for the runner (comma-separated):
Enter optional maintenance note for the runner:

Registering runner... succeeded                     runner=FSMwkvLZ
Please enter the executor: custom, docker, virtualbox, kubernetes, docker+machine, docker-ssh+machine, docker-ssh, parallels, shell, ssh:
docker
Please enter the default Docker image (for example, ruby:2.6):
ruby:2.6
Runner registered successfully. Feel free to start it, but if it's running already the config should be automatically reloaded!
```

Next, you must add some additional configuration to your runner.

Make the following changes to `/etc/gitlab-runner/config.toml`:

- Add Docker socket to volumes `volumes = ["/var/run/docker.sock:/var/run/docker.sock", "/cache"]`
- Add `pull_policy = "if-not-present"` to the executor configuration

Now you can start your runner:

```shell
sudo docker run -d --restart always --name gitlab-runner -v /etc/gitlab-runner:/etc/gitlab-runner -v /var/run/docker.sock:/var/run/docker.sock gitlab/gitlab-runner:latest
90646b6587127906a4ee3f2e51454c6e1f10f26fc7a0b03d9928d8d0d5897b64
```

### Authenticating the registry against the host OS

As noted in [Docker registry authentication documentation](https://distribution.github.io/distribution/about/insecure/#docker-still-complains-about-the-certificate-when-using-authentication),
certain versions of Docker require trusting the certificate chain at the OS level.

In the case of Ubuntu, this involves using `update-ca-certificates`:

```shell
sudo cp /etc/docker/certs.d/my-host.internal\:5000/ca.crt /usr/local/share/ca-certificates/my-host.internal.crt

sudo update-ca-certificates
```

If all goes well, this is what you should see:

```plaintext
1 added, 0 removed; done.
Running hooks in /etc/ca-certificates/update.d...
done.
```

### Disable version check and Service Ping

Stop offline instances from contacting `version.gitlab.com`.

In GitLab 17.10 to 19.5, clearing **Enable version check** does not stop the version check.
[Merge request 261398](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261398) fixes this in GitLab 19.6.

To stop an offline instance from contacting `version.gitlab.com`:

1. [Disable version check](../../administration/settings/usage_statistics.md#enable-or-disable-version-check).
1. [Disable Service Ping](../../administration/settings/usage_statistics.md#enable-or-disable-service-ping).

With an offline license, disabling Service Ping stops the instance from sending Service Ping.
With another license, the instance might still send it.

### Disable runner version management

Runner version management retrieves the latest runner versions from GitLab to
[determine which runners in your environment are out of date](../../ci/runners/runners_scope.md#determine-which-runners-need-to-be-upgraded).
You must [disable runner version management](../../administration/settings/continuous_integration.md#control-runner-version-management)
for offline environments.

### Configure NTP

Gitaly Cluster (Praefect) assumes `pool.ntp.org` is accessible. If `pool.ntp.org` is not accessible, [customize the time server setting](../../administration/gitaly/praefect/configure.md#customize-time-server-setting) on the Gitaly
and Praefect servers so they can use an accessible NTP server.

On offline instances, the [GitLab Geo check Rake task](../../administration/geo/replication/troubleshooting/common.md#can-geo-detect-the-current-site-correctly)
always fails because it uses `pool.ntp.org`. This error can be ignored but you can
[read more about how to work around it](../../administration/geo/replication/troubleshooting/common.md#message-machine-clock-is-synchronized--exception).

## Hosts that an instance contacts by default

{{< history >}}

- Billable usage events no longer sent to `billing.prdsub.gitlab.net` when an offline license is active [introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258078) in GitLab 19.5.

{{< /history >}}

By default, a GitLab instance with no internet access, or with controlled egress, tries to reach the hosts listed in the table below.

Use the table to:

- Decide which hosts to allow, if you're building a network allowlist.
- Find the setting that stops an instance from contacting a host.

GitLab Duo and the [Package Metadata Database](#enabling-the-package-metadata-database) contact additional hosts.

| Host | Sent by | Setting that stops it | Stopped by an offline license |
|------|---------|-----------------------|-------------------------------|
| `events.gitlab.net` | [Event tracking](../../administration/settings/event_data.md). | Clear **Enable event tracking**.[^events] | {{< no >}} |
| `observe.gitlab.com` | On GitLab Ultimate, a background job that runs every minute to fetch Observability alerts. | Clear **Fetch cloud observability alerts**.[^observe] | {{< no >}} |
| `billing.prdsub.gitlab.net` | GitLab, when it emits billable usage events. | None. **Enable event tracking** does not apply. | {{< yes >}} |
| `version.gitlab.com` | Version check and Service Ping. | Clear **Enable version check** and **Enable Service Ping**. For exceptions, see [disable version check and Service Ping](#disable-version-check-and-service-ping). | {{< no >}} |
| `snowplowstg.trx.gitlab.net` | Service Ping, which sends a connectivity test request to this host while it generates its payload. | Clear **Enable Service Ping**. For exceptions, see [disable version check and Service Ping](#disable-version-check-and-service-ping). | {{< no >}} |
| `gitlab.com` | Runner version management, when a registered runner has connected to the instance. | See [disable runner version management](#disable-runner-version-management). | {{< no >}} |
| `storage.googleapis.com` | On a license with dependency scanning, a background job that runs every hour to download CVE enrichment data, which vulnerability findings use for [risk assessment](../../user/application_security/vulnerabilities/risk_assessment_data.md). The advisory sync of the [Package Metadata Database](#enabling-the-package-metadata-database) also uses this host. | None. **Package registry metadata to sync** stops the advisory sync but not this download. To read the data from a local copy instead, see [Package Metadata Database for offline instances](package-metadata-database.md). | {{< no >}} |

[^events]: GitLab Duo events are still sent unless the instance has a self-hosted model configured.
    For the steps, see [enable or disable event-level data collection](../../administration/settings/event_data.md#enable-or-disable-event-level-data-collection).
[^observe]: If **Fetch cloud observability alerts** is not shown under **Admin** > **Settings** > **Network**,
    set `fetch_observability_alerts_from_cloud` to `false` with the
    [application settings API](../../api/settings.md#update-application-settings).

A GitLab instance with a host name that starts with `gitlab` and ends with `.test` instead sends:

- Events to `events-stg.gitlab.net`.
- Billable usage events to `billing.stgsub.gitlab.net`.

In GitLab 19.5 and later, so does an instance where the `CUSTOMER_PORTAL_URL` environment variable points to the staging Customers Portal. For more
information, see [merge request 256115](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256115).

## Enabling the Package Metadata Database

[Continuous vulnerability scanning](../../user/application_security/continuous_vulnerability_scanning/_index.md)
and [license scanning of CycloneDX files](../../user/compliance/license_scanning_of_cyclonedx_files/_index.md)
read the Package Metadata Database.
An offline instance cannot download it, so you download it on a machine with internet access and copy it
to the instance.

- For what the database holds and which data format version your GitLab version reads, see
  [Package Metadata Database](../../user/application_security/detect/package-metadata-database.md).
- For the download and copy procedures, see
  [Package Metadata Database for offline instances](package-metadata-database.md).
