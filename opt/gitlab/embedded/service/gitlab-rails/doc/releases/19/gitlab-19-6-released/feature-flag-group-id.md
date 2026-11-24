---
title: Group ID for feature flag rollout strategies
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: deploy
documentation_link: "../../../operations/feature_flags/#percent-rollout"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/263973
categories: [ Feature Flags ]
co_create: true
level: secondary
weight: 50
---

The percent rollout and percent-of-users feature flag strategies now accept a custom Group ID.
Strategies across flags that share the same Group ID and stickiness value select the same
user set at the same percentage, letting you coordinate rollout across multiple flags.
Change the Group ID to target an independent set of users instead.

Thank you to [Mehdi Youb](https://gitlab.com/myoub) for this contribution
([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/263973))!
