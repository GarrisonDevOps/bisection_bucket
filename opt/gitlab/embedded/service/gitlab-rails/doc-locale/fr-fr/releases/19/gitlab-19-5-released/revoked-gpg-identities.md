---
title: Les identités GPG révoquées ne vérifient plus les commits
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
co_create: true
documentation_link: "../../../user/project/repository/signed_commits/gpg/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255300
categories: [ Source Code Management ]
level: secondary
weight: 70
---

GitLab ignore désormais les identifiants utilisateur que GPG signale comme révoqués. Une identité révoquée n'apparaît plus sous **Accès** > **Clés GPG** dans les paramètres utilisateur et n'est plus comptabilisée comme un e-mail vérifié pour le badge **Vérifié** sur les commits signés. Les commits signés sous une identité révoquée sont déplacés vers « même utilisateur, e-mail différent » ou « autre utilisateur », et une clé dont toutes les identités sont révoquées ne vérifie rien. Les signatures déjà vérifiées sous une clé qui reste en place ne sont pas recalculées.

Merci à [José M. Requena Plens](https://gitlab.com/jmrp) pour cette contribution ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255300)) !
