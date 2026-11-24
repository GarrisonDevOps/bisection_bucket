---
title: Archive subgroup custom role ability
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: software_supply_chain_security
documentation_link: "../../../user/custom_roles/abilities/#groups-and-projects"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257968
categories: [ Permissions ]
co_create: true
level: secondary
weight: 70
---

You can now add the `archive_subgroup` ability to custom roles. Users with this ability
can archive and unarchive subgroups without needing the broader Owner role, which also
grants the ability to delete a group. The ability appears as **Archive subgroup** in the
custom role editor.

Thank you to [Jimmy Spagnola](https://gitlab.com/jspagnola) for this contribution
([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257968))!
