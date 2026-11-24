---
title: CITATION.cff file detection
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
documentation_link: "../../../user/project/repository/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254371
categories: [ Source Code Management ]
co_create: true
level: secondary
weight: 100
---

GitLab now detects `CITATION.cff` files in repositories.
Projects with a `CITATION.cff` file show a link to the file in the project overview.
Projects without one show an option to add a `CITATION.cff` file.
`CITATION.cff` is an open file format that describes how to cite software.

Thank you to [rajasekhar](https://gitlab.com/rajasekharponakala) for this contribution
([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254371))!
