---
title: Other improvements
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
co_create: true
documentation_link: "../../../user/model_context_protocol/mcp_server_troubleshooting/#error-rate_limited-tool-result"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256657
categories: [ Agent Tools ]
level: secondary
weight: 80
---

Other improvements in this release include:

- GitLab MCP server: rate-limited tool results name the limit and retry delay.
  ([otutukingsley](https://gitlab.com/otutukingsley), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256657))
- GitLab MCP server: `add_branch` returns the branch `web_url`.
  ([Jeston Singh](https://gitlab.com/sjestonsingh), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255143))
- GitLab MCP server: tool aliases in the enabled-tools header resolve.
  ([Jeston Singh](https://gitlab.com/sjestonsingh), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255111))
- GitLab MCP server: `add_branch` rejects mismatched URL and project ID inputs.
  ([ryo-whaletech](https://gitlab.com/ryo-whaletech), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254573))
- GitLab MCP server: `get_repository_file` rejects mismatched URL and project ID inputs.
  ([Mohamed Elsayed](https://gitlab.com/MooSayed11), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256268))
- GitLab MCP server: `ai_workflows` tokens can read blobs in batch.
  ([Jeston Singh](https://gitlab.com/sjestonsingh), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255142))
- Administrators in admin mode can set a cluster agent on an environment without joining
  the project. ([Gerardo Navarro](https://gitlab.com/gerardo-navarro), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169626))
- `CI_JOB_TAGS` and `CI_RUNNER_TAGS` JSON-encode each tag.
  ([ryo-whaletech](https://gitlab.com/ryo-whaletech), [MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256563), [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256718))
- Duplicate variable keys in push options are rejected. ([Jeston Singh](https://gitlab.com/sjestonsingh), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253823))
- Advanced SAST (Ultimate): C and C++ files up to 20 levels deep are scanned.
  ([Jeston Singh](https://gitlab.com/sjestonsingh), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254734))
- Advanced SAST (Ultimate): the report follows your artifact retention.
  ([Jeston Singh](https://gitlab.com/sjestonsingh), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254613))
- Plain-text token and SSH key emails link to the right page.
  ([Torben Buck](https://gitlab.com/torben.buck), [MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254859), [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255638))
- `?scopes=` links prefill the token form. ([Torben Buck](https://gitlab.com/torben.buck), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254871))
