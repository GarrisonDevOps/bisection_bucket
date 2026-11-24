---
title: Additional feature enhancements
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: verify
co_create: true
documentation_link: "../../../api/job_artifacts/#download-job-artifacts-by-job-id"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252518
categories: [ Job Artifacts ]
level: secondary
---

Other improvements in this release include:

- Fetch a specific report artifact from the API, restricted to downloadable types and gated by a
  per-artifact authorization check. For example, use
  `GET /projects/:id/jobs/:job_id/artifacts?file_type=junit` for a JUnit file.
  ([Andreas Kunze](https://gitlab.com/and2345), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252518))
- Administrators can let clients choose between a direct 302 redirect and a proxied transfer for
  job artifact and package downloads. ([André Düwel](https://gitlab.com/duewel1982), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252350))
- The pipeline editor now validates CI/CD keywords the backend already supported.
  ([Paweł Farys](https://gitlab.com/vertisan), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250636))
- An email with an empty subject line now opens a Service Desk ticket instead of bouncing.
  ([Praveen Arimbrathodiyil](https://gitlab.com/pravi), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248600))
- Raise dependency resolution limits yourself with two new timeout inputs on the
  `Dependency-Scanning.v2` template. ([Niklas van Schrick](https://gitlab.com/Taucher2003), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249426))
- Administrators can set achievements to appear on profiles without each person accepting an
  emailed link. ([BoxBoxJason](https://gitlab.com/BoxBoxJason), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249893))
