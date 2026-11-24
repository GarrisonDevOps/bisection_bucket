---
title: Configurer les limites de pipeline parallèle pour les merge trains
stage: verify
level: secondary
tier: [ Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
documentation_link: "../../../administration/cicd/limits/#merge-train-parallel-pipeline-limit"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/374188"
categories: [ Continuous Integration (CI) ]
weight: 90
---

Dans les versions précédentes de GitLab, vous ne pouviez pas modifier le maximum de 20 pipelines parallèles dans un merge train, ce qui vous forçait soit à surcharger vos runners, soit à abandonner complètement les merge trains. Vous pouvez désormais configurer la limite de pipelines parallèles par merge train pour équilibrer la charge des runners et le débit de merge. Vous pouvez définir la limite par projet ou à l'échelle de l'instance. Définir la limite à 1 signifie que chaque merge request s'exécute une à la fois, par rapport à une branche cible propre.

Merci à [Norman Debald (@Modjo85)](https://gitlab.com/Modjo85) pour cette contribution.
