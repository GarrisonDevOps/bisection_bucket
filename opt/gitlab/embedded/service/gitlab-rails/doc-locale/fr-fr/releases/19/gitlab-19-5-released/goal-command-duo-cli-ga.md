---
title: "La commande `/goal` dans GitLab Duo CLI est disponible en disponibilité générale"
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_cli/use/#slash-commands"
work_item: https://gitlab.com/groups/gitlab-org/ai-powered/-/work_items/10
categories: [ Duo CLI ]
level: secondary
weight: 50
---


La commande slash `/goal` dans GitLab Duo CLI est désormais disponible en disponibilité générale dans GitLab Duo CLI 9.27.0.

Décrivez un objectif ouvert, et GitLab Duo le délègue à un flow gouverné et orienté vers les objectifs qui s'exécute localement et gère à la fois l'implémentation et la vérification.

Pour commencer, exécutez `/goal <task>`. Par exemple :

```plaintext
/goal Fix the failing tests in spec/models/user_spec.rb
```

Dans GitLab 19.5 (GitLab Duo CLI 9.24.0), le paramètre **Exécuter les invites suggérées en tant que sessions /goal** dans `/settings` exécute les invites suggérées en tant que sessions `/goal` plutôt que comme messages de chat.

`/goal` nécessite GitLab 19.3 ou une version ultérieure, ainsi que GitLab Duo CLI 9.17.0 ou une version ultérieure.
