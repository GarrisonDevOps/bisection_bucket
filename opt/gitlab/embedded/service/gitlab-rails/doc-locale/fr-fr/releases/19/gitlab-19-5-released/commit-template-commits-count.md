---
title: Variable de comptage des commits dans les modèles de commit
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
co_create: true
documentation_link: "../../../user/project/merge_requests/commit_templates/#supported-variables-in-commit-templates"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255231
categories: [ Code Review Workflow ]
level: secondary
weight: 50
---

Vous pouvez désormais utiliser `%{commits_count}` dans les modèles de messages de merge commit et de squash commit, ainsi que dans les nouveaux modèles de description de merge request. Par exemple, `%{title} (%{commits_count} commits)` s'affiche sous la forme `Bugfix (3 commits)`.

Merci à [Jeston Singh](https://gitlab.com/sjestonsingh) pour cette contribution ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255231)) !
