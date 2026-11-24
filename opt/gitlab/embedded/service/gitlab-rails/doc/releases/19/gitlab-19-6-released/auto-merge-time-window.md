---
title: Set a time window for automatic merge
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
documentation_link: "../../../user/project/merge_requests/auto_merge/#prevent-merge-outside-a-specific-time-period"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258025
categories: [ Code Review Workflow ]
co_create: true
level: secondary
weight: 10
---

You can now set a time range for a merge schedule to merge automatically.
In previous versions of GitLab, the merge schedule supported only the **After** option,
which prevented a merge before the date you set.
Now you can select **Between** to define a window: the merge request merges only when the
current time falls between the two dates you set.

Thank you to [Niklas van Schrick](https://gitlab.com/Taucher2003) for these contributions
([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258024)
[MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258025)
[MR 3](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/262275))!
