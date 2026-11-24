---
title: Workspaces support ARM64 Kubernetes clusters
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
documentation_link: "../../../user/workspace/configuration/#platform-compatibility"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/264361
categories: [ Workspaces ]
co_create: true
level: secondary
weight: 60
---

GitLab Workspaces now run native images on `linux/arm64` Kubernetes nodes, including
Apple M-series hardware. Previously, arm64 nodes ran the amd64 image under emulation.
GitLab pulls the correct image variant for each node automatically.
Custom devfile images must support the architecture of the node where the workspace runs.

Thank you to [Miguel Sacristan](https://gitlab.com/miguel.sacristan1) for this contribution
([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/264361))!
