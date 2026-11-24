---
title: Web search in GitLab Duo Agentic Chat
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_chat/agentic_chat/#web-search"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/20480
categories: [ Web Chat ]
level: secondary
weight: 50
---

Previously, GitLab Duo Agentic Chat couldn't look up current information.
It answered only from the model's training data and your GitLab context.
Answers about things like the latest package version or a security advisory
might be out of date.

Now you can turn on web search in a conversation.
Chat searches the web and reads pages to find current answers,
so you don't have to leave GitLab.
Expand each search in the conversation to see the pages it found.
Each search also creates an audit event.

Web search is off by default.
On GitLab.com, a group Owner must allow it for the top-level group.
On GitLab Self-Managed and GitLab Dedicated, an administrator must allow it for the instance.
