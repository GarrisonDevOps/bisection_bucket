---
title: Configurer la fréquence de mise à jour des job logs
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
stage: verify
co_create: true
documentation_link: "../../../administration/settings/continuous_integration/#configure-the-frequency-of-job-log-updates"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251401
categories: [ Continuous Integration (CI) ]
level: secondary
weight: 30
---

Les administrateurs peuvent désormais définir la fréquence de mise à jour des job logs, sous **Espace d’administration** > **Paramètres** > **CI/CD** ou via l'API Settings. Vous pouvez choisir une valeur comprise entre 3 et 3600 secondes. Dans les versions précédentes de GitLab, ces intervalles étaient des constantes, de sorte qu'il était impossible de réduire le délai initial du live log pour les jobs courts sans modifier l'instance.

Merci à [Aleksandr Kotlyar](https://gitlab.com/aleksandr-kotlyar) pour cette contribution ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251401)) !
