---
title: "Déclencheur d'événement de merge request prête"
stage: ai-powered
level: secondary
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed ]
documentation_link: "../../../user/duo_agent_platform/triggers/"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/592454"
categories: [ Duo Agent Platform ]
weight: 30
---

Vous pouvez désormais configurer des flows et des agents externes pour s'exécuter sur l'événement **Merge request prête**.

Lorsqu'une merge request en brouillon est marquée comme prête pour la revue, GitLab Duo exécute automatiquement le flow ou l'agent externe.

Pour configurer un déclencheur, accédez à **IA** > **Déclencheurs** dans votre projet.

Cette fonctionnalité est protégée par le feature flag `merge_request_ready_flow_trigger`, désactivé par défaut.
