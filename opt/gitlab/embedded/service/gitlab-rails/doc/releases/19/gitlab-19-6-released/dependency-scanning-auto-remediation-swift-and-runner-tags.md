---
title: Dependency scanning auto-remediation with Swift support and runner tags
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: software_supply_chain_security
documentation_link: "../../../user/application_security/remediate/dependency_scanning_auto_remediation/"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/19244
categories: [ Software Composition Analysis ]
level: secondary
---

Dependency scanning auto-remediation opens merge requests that bump the versions of vulnerable
dependencies. Previously, Swift projects were not supported, and the job ran only on untagged runners.
Merge requests went to a random maintainer, and each project could have at most 10 open at once.

In GitLab 19.6:

- Swift Package Manager projects with a committed `Package.resolved` file now get
  auto-remediation merge requests.
- You can set runner tags on an auto-remediation profile and the job runs on matching runners.
- With automatic reviewer assignment turned on, the Code Owners of the updated files are
  requested as reviewers. Otherwise, GitLab assigns no reviewer.
- Each project can have up to 30 open auto-remediation merge requests.
- Titles and commit messages follow Conventional Commits when your repository does.

For details, see [dependency scanning auto-remediation](../../../user/application_security/remediate/dependency_scanning_auto_remediation.md).
