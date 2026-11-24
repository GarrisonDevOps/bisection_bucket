---
title: "Deux nouvelles variables CI/CD : nombre de tentatives et tags de job"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
co_create: true
documentation_link: "../../../ci/variables/predefined_variables/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/?sort=created_date&state=merged&milestone_title=19.3&label_name%5B%5D=Community%20contribution&label_name%5B%5D=release%20post%20item&label_name%5B%5D=group%3A%3Apipeline%20authoring
categories: [ Pipeline Composition ]
level: secondary
---

Vos scripts de pipeline peuvent désormais déterminer s'ils s'exécutent pour la première fois. `CI_JOB_RETRY_COUNT` indique combien de fois le job actuel a été relancé et vaut `0` lors de la première exécution. La logique sensible aux nouvelles tentatives n'a donc plus besoin d'assurer le suivi de l'état elle-même. Par ailleurs, `CI_JOB_TAGS` expose les tags configurés pour le job, alors qu'auparavant seuls les tags du runner étaient visibles via `CI_RUNNER_TAGS`. Ces deux variables sont disponibles sans aucune configuration.

Merci à [Giannis Kepas](https://gitlab.com/gkepas) et à [Dwight Blake](https://gitlab.com/lunivilen) pour ces contributions !
