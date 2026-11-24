---
title: Mode automatique dans GitLab Duo CLI
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_cli/use/#auto-mode"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23697
categories: [ Duo CLI ]
level: secondary
weight: 50
---

GitLab Duo CLI dispose d'un nouveau mode automatique. En mode automatique, GitLab Duo utilise des outils sans demander d'approbation au préalable, ce qui permet aux tâches plus longues de s'exécuter sans s'interrompre pour chaque commande shell, opération `git`, ou appel d'outil MCP.

Le mode automatique respecte les contrôles de votre organisation :

- Le mode automatique est désactivé par défaut. Les administrateurs, les propriétaires et les mainteneurs peuvent activer ce paramètre pour les instances, les groupes et les projets. Les administrateurs et les propriétaires de groupe peuvent également le verrouiller sur **Toujours désactivée** pour l'ensemble de l'instance ou du groupe.
- La gouvernance des outils des agents s'applique toujours. Les outils définis sur **Toujours refuser** restent bloqués.

Pour utiliser le mode automatique, vous devez disposer de GitLab Duo CLI 9.22.0 ou version ultérieure. Appuyez sur <kbd>Tab</kbd> jusqu'à ce que le mode affiché sous l'invite `>` indique `auto`. Utilisez le mode automatique uniquement dans les dépôts auxquels vous faites confiance et sur les branches que vous pouvez supprimer.
