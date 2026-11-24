---
title: Plugins et marketplaces GitLab Duo CLI (version expérimentale)
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_cli/customize/#plugins"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/22497
categories: [ Duo CLI ]
level: secondary
weight: 50
---

GitLab Duo CLI prend désormais en charge les plugins et les marketplaces de plugins à titre expérimental, une fonctionnalité introduite dans GitLab Duo CLI 9.10.0. Un plugin regroupe des Agent Skills, des commandes slash personnalisées et des serveurs Model Context Protocol (MCP) dans un seul répertoire. Un marketplace est un catalogue de plugins disponibles, hébergé dans un dépôt Git ou un répertoire local.

GitLab Duo CLI enregistre automatiquement le marketplace officiel `gitlab-duo-plugins` la première fois que vous utilisez des plugins.

Le marketplace comprend trois skills pour les workflows GitLab courants :

- `mr-review` : révise une merge request et publie des commentaires.
- `stack-changes` : divise une grande modification locale en une chaîne de merge requests empilées.
- `create-issue` : rédige un ticket GitLab à partir d'une description en langage naturel.

Pour installer l'un des skills, exécutez `glab duo cli plugin install <plugin>@gitlab-duo-plugins` ou `duo plugin install <plugin>@gitlab-duo-plugins`, selon votre configuration.

Pour assurer la compatibilité avec l'écosystème existant de plugins communautaires, GitLab Duo CLI lit également les fichiers `.claude-plugin/marketplace.json`, de sorte que les marketplaces de plugins Claude Code existants fonctionnent avec GitLab Duo CLI sans modification.
