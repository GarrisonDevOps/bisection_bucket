---
title: Remédiation automatique des dépendances vulnérables (version expérimentale)
stage: software_supply_chain_security
level: secondary
tier: [ Ultimate ]
offering: [ gitlab_com ]
documentation_link: "../../../user/application_security/remediate/auto_remediation/"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/17403"
categories: [ Software Composition Analysis ]
weight: 10
---

La remédiation automatique pour les dépendances est désormais disponible en tant que version expérimentale dans GitLab 19.0. Lorsque l'analyse des dépendances détecte une dépendance Ruby vulnérable avec un correctif connu, GitLab ouvre automatiquement une merge request pour la mettre à jour vers une version sûre sans intervention humaine. Seuls les projets Ruby sont pris en charge dans la version expérimentale.

Après chaque pipeline, GitLab identifie la vulnérabilité de la plus haute gravité avec un correctif ou une mise à niveau de version mineure disponible. GitLab génère la modification du fichier manifeste et ouvre une merge request via un compte de service. La merge request passe ensuite par le workflow standard de revue et d'approbation de votre projet.

Pendant la version expérimentale, jusqu'à trois merge requests de remédiation automatique peuvent être ouvertes par projet à la fois.

Pour partager vos commentaires ou demander à participer à la version expérimentale, laissez un commentaire sur [l'epic 600511](https://gitlab.com/gitlab-org/gitlab/-/work_items/600511). Pour activer la version expérimentale sur votre projet, un membre de l'équipe GitLab doit activer le feature flag `dependency_management_auto_remediation` pour votre projet.
