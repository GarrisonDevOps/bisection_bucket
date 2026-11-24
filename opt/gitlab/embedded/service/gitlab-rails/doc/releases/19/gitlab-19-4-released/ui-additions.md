---
title: Other additions to the interface
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: plan
co_create: true
documentation_link: "../../../user/project/issues/managing_issues/#filter-the-list-of-issues"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250014
categories: [ Team Planning ]
level: secondary
---

Other additions to the interface in this release include:

- Filtering the issue list by created, closed, due, and updated date is now generally available
  for everyone. ([Radek Antoniuk](https://gitlab.com/rantoniuk), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250014))
- Starting a merge request from a cherry-picked commit now has a checkbox to copy the source
  merge request's description instead of the project template.
  ([Viktor Chekryzhov](https://gitlab.com/Vchekryzhov1), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248574))
- `/internal_note` marks a comment internal as you create it, so internal notes can live inside
  comment templates and saved replies. ([Priyansh Garg](https://gitlab.com/priyansh3133), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/243383))
- `/type Epic` promotes an issue to an epic, the same as `/promote_to Epic`.
  ([Aryann Dwivedi](https://gitlab.com/aryanndwivedi2403), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241880))
- Links in Mermaid flowcharts now open. ([skkzsh](https://gitlab.com/skkzsh), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253987))
- Mermaid diagrams render without clipping in Chrome on iOS. ([Jordan Labrosse](https://gitlab.com/Jorgagu), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250484))
