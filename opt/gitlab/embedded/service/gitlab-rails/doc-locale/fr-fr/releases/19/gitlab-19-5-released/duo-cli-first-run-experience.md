---
title: "Amélioration de l'expérience de première utilisation dans GitLab Duo CLI"
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_cli/use/#startup-cards"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/22187
categories: [ Duo CLI ]
level: secondary
weight: 50
---

GitLab Duo CLI aide désormais les nouveaux utilisateurs à démarrer sans quitter le terminal :

- Au premier lancement, une carte d'intégration vous aide à connecter des serveurs MCP et à installer des plugins GitLab.
- Chaque nouvelle session s'ouvre avec des invites suggérées à partir de vos merge requests et tickets ouverts. Pour une invite de merge request, GitLab Duo extrait d'abord la branche source si elle existe.
- La barre de statut affiche votre branche, votre projet, votre merge request, la progression de `/goal` et le statut MCP.
- L'écran de configuration renvoie vers la création de jetons et valide votre jeton avant l'enregistrement.
- Les conseils dans l'invite et la commande `/whatsnew` vous orientent vers les nouvelles fonctionnalités.

Pour bénéficier de l'expérience complète, mettez à jour GitLab Duo CLI vers la version 9.28.0 ou ultérieure.
