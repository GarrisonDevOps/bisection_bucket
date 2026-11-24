---
title: GitLab Duo approves or requests changes (beta)
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
documentation_link: "../../../user/duo_agent_platform/flows/foundational_flows/code_review/#approvals-and-change-requests"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23854
categories: [ DAP Code Review ]
level: secondary
---

In previous versions of GitLab, Code Review Flow could only leave comments.
It could not approve or block a merge.

Now GitLab Duo can approve or request changes based on its review:

- With nothing to comment on, GitLab Duo approves the merge request.
  The approval does not count toward required approvals.
- With findings to comment on, GitLab Duo requests changes.
  If your project blocks merges on a request for changes, a request from GitLab Duo blocks a merge too.
  The request stays until GitLab Duo approves in a follow-up review, or a user bypasses it.

To use this feature, [turn on experiment and beta features](../../../user/duo_agent_platform/turn_on_off.md#turn-on-beta-and-experimental-features),
then turn on **GitLab Duo can approve and request changes** for your project, group, or instance.
