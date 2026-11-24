---
title: "Passerelle d'IA pour GitLab Dedicated"
tier: [ Ultimate ]
offering: [ gitlab_dedicated ]
stage: gitlab_dedicated
documentation_link: "../../../administration/gitlab_duo_self_hosted/supported_llm_serving_platforms/#configure-authentication-with-aws-bedrock"
work_item: https://gitlab.com/gitlab-com/gl-infra/gitlab-dedicated/team/-/work_items/13486
categories: [ GitLab Dedicated ]
level: secondary
---

La passerelle d'IA pour GitLab Dedicated s'exécute dans votre environnement AWS, dans la même région que votre instance GitLab Dedicated. Les requêtes d'inférence, notamment les entrées de code, les invites et les réponses des modèles, restent au sein de votre réseau et de votre région. Toutes les requêtes d'inférence de la plateforme GitLab Duo Agent restent dans la même portée d'audit que votre instance GitLab Dedicated. La passerelle d'IA pour GitLab Dedicated est activée par défaut, sans aucune configuration requise.

Si vous le souhaitez, vous pouvez utiliser Bring Your Own Model (BYOM) pour vous connecter à vos propres modèles hébergés dans le cloud. Vous pouvez alimenter les fonctionnalités de la plateforme GitLab Duo Agent avec les modèles de votre choix, dans votre région, sous vos contrôles d'accès.
