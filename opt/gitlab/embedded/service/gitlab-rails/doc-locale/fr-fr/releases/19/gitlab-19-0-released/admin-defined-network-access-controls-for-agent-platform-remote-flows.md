---
title: "Contrôles d'accès réseau définis par l'administrateur pour les flows distants de l'Agent Platform"
stage: ai-powered
level: secondary
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
documentation_link: "../../../user/duo_agent_platform/environment_sandbox/#configure-a-network-policy"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/593149"
categories: [ Duo Agent Platform ]
weight: 110
---

Les administrateurs peuvent désormais définir des politiques réseau centralisées pour les flows distants de GitLab Duo Agent Platform directement dans les paramètres. Les administrateurs de groupe principal sur GitLab.com, et les administrateurs d'instance sur GitLab Self-Managed et GitLab Dedicated, peuvent configurer des listes de blocage et des listes d'autorisation de domaines à l'échelle de l'organisation que les projets héritent automatiquement. Un paramètre supplémentaire contrôle si les projets peuvent étendre la liste des domaines approuvés avec des entrées personnalisées. Les politiques sont appliquées au moment de l'exécution sur tous les flows distants, offrant aux équipes de sécurité et de plateforme une couche de gouvernance cohérente pour les sorties réseau des agents.
