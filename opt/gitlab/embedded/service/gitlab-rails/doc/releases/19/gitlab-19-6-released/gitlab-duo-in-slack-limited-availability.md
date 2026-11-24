---
title: GitLab Duo in Slack is now in limited availability on GitLab.com
tier: [ Premium, Ultimate ]
offering: [ gitlab_com ]
stage: agent_foundations
documentation_link: "../../../user/project/integrations/gitlab_slack_application/#gitlab-duo"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/638482
categories: [ External Agents ]
level: primary
weight: 50
---

GitLab Duo in Slack is now in limited availability on GitLab.com. Mention `@GitLab` in a Slack channel or thread
to turn a conversation into an issue, summarize a discussion, search for issues and merge requests,
or ask questions about your projects. GitLab Duo reads the conversation as context and posts the result back in Slack.

Setup is simpler too. An Owner installs the GitLab for Slack app on a top-level group. All GitLab Duo sessions from that Slack workspace then run in that group and use its GitLab Duo settings and credits.

Users with at least the Developer role connect their own GitLab account the first time they mention `@GitLab`.
