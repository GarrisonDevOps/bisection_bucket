---
title: Configurable limits for pipeline variables
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: verify
documentation_link: "../../../administration/cicd/limits/#limit-pipeline-variables"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253433
categories: [ Pipeline Composition ]
level: secondary
weight: 50
---

Administrators can now limit the number and size of pipeline variables that can exist in a single pipeline. This helps maintain the stability of your CI/CD infrastructure by blocking users from adding too many large pipeline variables to their pipelines.

The limits are disabled by default for GitLab Self-Managed and GitLab Dedicated.
For GitLab.com, the limits are:

- 1,200 variables per pipeline
- 128 KiB per value
- 1 MiB per file type value
