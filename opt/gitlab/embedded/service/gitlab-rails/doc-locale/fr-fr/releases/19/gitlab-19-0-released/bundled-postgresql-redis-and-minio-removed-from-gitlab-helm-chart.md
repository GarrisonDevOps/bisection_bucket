---
title: "Suppression des composants PostgreSQL, Redis et MinIO intégrés du chart Helm GitLab"
stage: gitlab_delivery
level: secondary
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed ]
documentation_link: "https://docs.gitlab.com/charts/installation/migration/bundled_chart_migration/"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/590797"
categories: [ Cloud Native Installation ]
weight: 80
---

Les charts Bitnami PostgreSQL, Bitnami Redis et MinIO inclus sont supprimés du chart Helm GitLab et de GitLab Operator dans GitLab 19.0 sans remplacement. Ces composants étaient destinés uniquement aux environnements de preuve de concept et de test et ne sont pas recommandés pour une utilisation en production. Si vous exécutez une instance avec l'un de ces services inclus, suivez le [guide de migration](https://docs.gitlab.com/charts/installation/migration/bundled_chart_migration/) pour configurer des services externes avant de mettre à niveau vers GitLab 19.0.
