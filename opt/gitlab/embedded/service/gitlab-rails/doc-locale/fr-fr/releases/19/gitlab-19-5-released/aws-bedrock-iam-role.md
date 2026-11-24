---
title: Rôles IAM pour les modèles auto-hébergés Amazon Bedrock
tier: [ Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
stage: ai_platform
documentation_link: "../../../administration/gitlab_duo_self_hosted/supported_llm_serving_platforms/#assume-an-iam-role-with-aws-bedrock"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/542393
categories: [ Model Selection ]
level: secondary
weight: 50
---

Auparavant, vous ne pouviez pas contrôler les informations d'identification AWS que la passerelle d'IA utilisait pour vos modèles Amazon Bedrock. Une seule identité AWS devait avoir accès à l'ensemble de ces modèles.

Avec cette release, vous pouvez spécifier un rôle IAM pour chaque modèle, et la passerelle d'IA assume ce rôle lors de l'appel au modèle. De cette façon, chaque modèle n'obtient que les accès AWS dont il a besoin, même lorsque le rôle se trouve dans un autre compte AWS.
