---
title: Resynchroniser à la demande un utilisateur bloqué par LDAP
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
stage: security_platform
co_create: true
documentation_link: "../../../administration/moderate_users/#resync-a-user-blocked-by-ldap"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255974
categories: [ System Access ]
level: secondary
weight: 10
---

Les administrateurs peuvent désormais resynchroniser un seul utilisateur bloqué par LDAP depuis la page **Utilisateurs** de la zone d'administration. La nouvelle action **Resynchroniser avec LDAP** effectue une vérification des accès LDAP et débloque l'utilisateur lorsque LDAP autorise l'accès, ou laisse l'utilisateur bloqué dans le cas contraire. Si l'utilisateur n'a pas d'identité LDAP, l'action est refusée avec un message. Dans les versions précédentes de GitLab, un compte bloqué par LDAP restait bloqué jusqu'à l'exécution de la synchronisation quotidienne des utilisateurs ou jusqu'à ce que l'utilisateur se connecte, ce que les comptes de service ne peuvent pas faire.

Merci à [Sergey Pechenko](https://gitlab.com/tnt4brain) pour cette contribution ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255974)) !
