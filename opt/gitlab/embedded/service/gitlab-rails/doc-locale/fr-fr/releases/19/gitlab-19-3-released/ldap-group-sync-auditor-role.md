---
title: La synchronisation des groupes LDAP peut désormais gérer le rôle Auditeur
tier: [ Premium, Ultimate ]
offering: [ self_managed ]
stage: software_supply_chain_security
co_create: true
documentation_link: "../../../administration/auth/ldap/ldap_synchronization/#assign-an-auditor-role-to-an-ldap-group"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/247042
categories: [ System Access ]
level: secondary
---

Vous pouvez désormais utiliser la synchronisation des groupes LDAP pour les instances GitLab Self-Managed afin d'accorder et de révoquer automatiquement le rôle Auditeur. Un nouveau paramètre `audit_group` associe un groupe LDAP au rôle Auditeur, de la même façon que `admin_group` le fait déjà pour les administrateurs, de sorte que l'accès auditeur suit l'appartenance à l'annuaire plutôt que d'être géré manuellement.

Merci à [Sergey Pechenko](https://gitlab.com/tnt4brain) pour cette contribution !
