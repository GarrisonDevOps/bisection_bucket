---
title: "Restreindre l'accès à GitLab Duo par appartenance à un sous-groupe"
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
stage: security_governance
documentation_link: "../../../administration/gitlab_duo/configure/access_control"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/633488
categories: [ AI Governance ]
level: primary
weight: 50
---

Les administrateurs peuvent désormais sélectionner n'importe quel sous-groupe, et pas uniquement des groupes principaux, dans le paramètre [**Restreindre l'accès en fonction de l'appartenance à un groupe**](../../../administration/gitlab_duo/configure/access_control.md) de GitLab Duo. Vous pouvez limiter la portée de l'accès à GitLab Duo Agent Platform à une équipe spécifique ou à un groupe pilote, sans avoir à restructurer votre hiérarchie de groupes.

Auparavant, ce paramètre acceptait uniquement les groupes principaux. Les organisations disposant d'un seul groupe principal pour l'ensemble des utilisateurs ne disposaient d'aucune méthode prise en charge pour limiter l'accès à GitLab Duo Agent Platform à un sous-ensemble d'utilisateurs.

Désormais, lorsque vous sélectionnez un sous-groupe, les membres directs de ce sous-groupe obtiennent l'accès. Cela facilite le déploiement d'un pilote GitLab Duo Agent Platform ou le déploiement progressif de l'accès, division par division, sur GitLab Self-Managed et GitLab Dedicated.
