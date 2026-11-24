---
title: Other additions to the interface
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
co_create: true
documentation_link: "../../../user/project/merge_requests/approvals/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258534
categories: [ Code Review Workflow ]
level: secondary
weight: 90
---

Other additions to the interface in this release include:

- Changing **Approvals required** in merge request settings shows a toast on success and
  an alert on failure. ([Sahil Bhatt](https://gitlab.com/Sahil8383), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258534))
- A compliance framework whose requirement already has 5 controls can be edited again.
  ([Sahil Bhatt](https://gitlab.com/Sahil8383), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258009))
- A failed protected environment update shows the API message.
  ([Jeston Singh](https://gitlab.com/sjestonsingh), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255147))
- In the **Create branch** dialog, the submit button stays disabled until the branch name is
  validated. ([Vladislav Petrov](https://gitlab.com/plus3x), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256907))
- Archived labels show an **Archived** tooltip in issue and merge request lists.
  ([Nicholas Wittstruck](https://gitlab.com/nwittstruck), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251069))
- Archived labels cannot be newly assigned. ([ryo-whaletech](https://gitlab.com/ryo-whaletech), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255219))
- SCIM tokens cannot be generated while the group's SAML provider is disabled.
  ([Sergey Pechenko](https://gitlab.com/tnt4brain), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249242))
- `.4dm` files are syntax highlighted. ([Logan Swartzendruber](https://gitlab.com/loganswartz), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257688))
- Right-aligned Markdown table columns use fixed-width numerals.
  ([Steve Mokris](https://gitlab.com/smokris), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254031))

Approval rules, compliance frameworks, and protected environments require Premium or Ultimate.
