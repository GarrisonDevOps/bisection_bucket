---
title: Restrict Jira Cloud domain access
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed ]
stage: plan
documentation_link: "../../../administration/settings/jira_cloud_app/#restrict-jira-domains-that-can-install-the-app"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256324
categories: [ Team Planning ]
co_create: true
level: secondary
weight: 30
---

Administrators can now configure a domain allowlist for the GitLab for Jira Cloud app.
Jira sites that are not on the allowlist can't install the app. Upgrading or reinstalling
the app also fails for those sites, so add every Jira site that is already connected before
you save the allowlist. An empty allowlist allows all domains, preserving the previous
behavior. The allowlist applies only to the Connect version of the app, not the Forge version.

Thank you to [Roger Meier](https://gitlab.com/bufferoverflow) for this contribution
([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256324))!
