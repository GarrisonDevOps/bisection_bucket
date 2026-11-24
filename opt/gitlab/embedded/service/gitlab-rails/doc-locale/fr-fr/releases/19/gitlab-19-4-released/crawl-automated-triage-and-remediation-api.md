---
title: Profil de triage et de remédiation automatisés (API GraphQL)
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/configuration/security_configuration_profiles/#automated-triage-and-remediation-profile"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23191
categories: [ Vulnerability Management ]
weight: 50
---

Dans les versions précédentes de GitLab, vous activiez la détection des faux positifs SAST, la résolution des vulnérabilités GitLab Duo, la détection des faux positifs de la détection des secrets et la remédiation automatique de l'analyse des dépendances pour chaque projet individuellement. Vous pouvez désormais appliquer un profil de triage et de remédiation automatisés à un groupe ou un projet, en définissant les niveaux de gravité et les modes d'exécution en une seule action. Commencez avec un préréglage ou configurez chaque flow vous-même :

- Conservateur : à la demande, gravité élevée.
- Standard : automatique, gravité moyenne et supérieure.
- Proactif : automatique, toutes les gravités.

Les profils sont disponibles uniquement via l'API GraphQL et nécessitent la plateforme GitLab Duo Agent avec les flows par défaut activés pour le groupe principal. La plupart des flows consomment des GitLab Credits.
