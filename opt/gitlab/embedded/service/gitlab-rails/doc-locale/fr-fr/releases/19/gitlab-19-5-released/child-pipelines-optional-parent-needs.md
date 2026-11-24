---
title: Les pipelines enfants peuvent dépendre optionnellement des jobs parents
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: verify
co_create: false
documentation_link: "../../../ci/yaml/#needspipelinejob"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/349538
categories: [ Continuous Integration (CI) ]
level: secondary
weight: 20
---

De nombreuses équipes de développement divisent les configurations CI/CD volumineuses en pipelines parents et enfants afin de faciliter la gestion de chaque partie. Jusqu'à présent, un job de pipeline enfant ne pouvait pas dépendre de manière fiable d'un job parent qui ne s'exécute que sous certaines conditions, comme des tests ne s'exécutant que lorsque certains fichiers sont modifiés. Si ce job parent était ignoré, le job enfant échouait, obligeant les équipes à contourner le problème avec des jobs en double ou des scripts fragiles.

Vous pouvez désormais marquer ces dépendances comme optionnelles. Si le job parent s'exécute, le job enfant l'attend comme d'habitude. S'il ne s'exécute pas, le job enfant continue sans lui. Les pipelines restent rapides et fiables sans contournements, et l'échec d'un job qui s'exécute arrête toujours le pipeline, de sorte que les contrôles qualité ne sont pas affaiblis.

Merci à [Jimmy Spagnola](https://gitlab.com/jspagnola) pour cette contribution !
