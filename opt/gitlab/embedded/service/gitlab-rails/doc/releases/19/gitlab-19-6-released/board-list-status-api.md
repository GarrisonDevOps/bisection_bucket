---
title: Status-based board lists in the REST API
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: plan
documentation_link: "../../../api/boards/#create-a-board-list"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/260752
categories: [ Planning Views ]
co_create: true
level: secondary
weight: 80
---

The board list REST API endpoints now accept a `status_id` parameter, letting you create
board columns that filter issues by a custom status. The API response includes the full
status object so your automation can read back the status it set.
In previous versions of GitLab, status-based lists could not be created through the REST API.

Thank you to [Daniel Ziegenberg](https://gitlab.com/ziegenberg) for this contribution
([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/260752))!
