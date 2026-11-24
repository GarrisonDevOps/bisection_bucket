---
stage: Developer Experience
group: Application Lifecycle
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Isolated installation.
title: Offline GitLab
---

{{< details >}}

- Tier: Free, Premium, Ultimate
- Offering: GitLab Self-Managed

{{< /details >}}

Computers in an offline environment are isolated from the public internet as a security measure. This
page lists all the information available for running GitLab in an offline environment.

## Quick start

If you plan to deploy a GitLab instance on a physically-isolated and offline network, see the
[quick start guide](quick_start_guide.md) for configuration steps.

## Features

Follow these best practices to use GitLab features in an offline environment:

- [Operating the GitLab Secure scanners in an offline environment](../../user/application_security/offline_deployments/_index.md).
- [Deploying GitLab Duo Self-Hosted in an offline environment](../../administration/gitlab_duo_self_hosted/offline_deployment.md).

## Container images for a Helm chart installation

If you install GitLab with the Helm chart, the images you deploy depend on the chart version
and your values.

Before you transfer images into the offline environment, list the images the chart deploys.
On a computer with internet access, run `helm template` with the values file you plan to use.

For more information, see
[Use custom Docker images for the GitLab chart](https://docs.gitlab.com/charts/advanced/custom-images/#current-images-and-tags).
