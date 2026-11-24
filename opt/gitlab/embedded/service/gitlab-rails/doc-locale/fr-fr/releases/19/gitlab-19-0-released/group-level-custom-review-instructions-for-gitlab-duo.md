---
title: Instructions de révision personnalisées au niveau du groupe pour GitLab Duo
stage: ai-powered
level: primary
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
documentation_link: "../../../user/gitlab_duo/customize_duo/review_instructions/#configure-custom-review-instructions-for-a-group"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/21504"
categories: [ Duo Code Review ]
add_ons: [ GitLab Duo Enterprise ]
weight: 10
---

Dans les versions précédentes de GitLab, vous ne pouviez définir des instructions de revue personnalisées pour GitLab Duo qu'au niveau du projet. Les équipes travaillant sur de nombreux projets dans le même groupe devaient dupliquer les mêmes instructions dans chaque projet.

Vous pouvez désormais configurer des instructions de revue personnalisées partagées pour un groupe entier et ses sous-groupes.

Sélectionnez un projet dans votre groupe à utiliser comme template. Lorsque GitLab Duo effectue une revue de code, il combine le fichier `.gitlab/duo/mr-review-instructions.yaml` au niveau du groupe avec toutes les instructions définies dans le projet individuel.

Le flow Code Review et GitLab Duo Code Review prennent tous deux en charge les instructions personnalisées au niveau du groupe.
