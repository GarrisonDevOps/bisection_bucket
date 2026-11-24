---
title: Autres améliorations
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
co_create: true
documentation_link: "../../../user/model_context_protocol/mcp_server_troubleshooting/#error-rate_limited-tool-result"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256657
categories: [ Agent Tools ]
level: secondary
weight: 80
---

Cette release inclut également les améliorations suivantes :

- Serveur MCP GitLab : les résultats d'outils soumis à une limite de débit indiquent la limite et le délai avant nouvelle tentative, `add_branch` retourne la branche `web_url`, les alias d'outils dans l'en-tête des outils activés sont résolus, les entrées d'URL et d'ID de projet non concordantes sont rejetées, et les jetons `ai_workflows` peuvent lire des blobs par lot.
- Les administrateurs en mode admin peuvent définir un agent de cluster sur un environnement sans rejoindre le projet.
- `CI_JOB_TAGS` et `CI_RUNNER_TAGS` encodent chaque tag en JSON. Les clés de variables dupliquées dans les options de push sont rejetées.
- SAST avancé (GitLab Ultimate) : les fichiers C et C++ jusqu'à 20 niveaux de profondeur sont analysés, et le rapport suit votre politique de rétention des artefacts.
- Les e-mails relatifs aux jetons en texte brut et aux clés SSH renvoient vers la bonne page, et les liens `?scopes=` préremplissent le formulaire de jeton.

Merci aux utilisateurs suivants pour leurs contributions !

- [otutukingsley](https://gitlab.com/otutukingsley) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256657))
- [Jeston Singh](https://gitlab.com/sjestonsingh) ([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255143) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255111) [MR 3](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255142) [MR 4](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253823) [MR 5](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254734) [MR 6](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254613))
- [ryo-whaletech](https://gitlab.com/ryo-whaletech) ([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254573) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256563) [MR 3](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256718))
- [Mohamed Elsayed](https://gitlab.com/MooSayed11) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256268))
- [Gerardo Navarro](https://gitlab.com/gerardo-navarro) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169626))
- [Torben Buck](https://gitlab.com/torben.buck) ([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254859) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255638) [MR 3](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254871))
