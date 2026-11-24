---
title: "Nouvelles façons de filtrer et de gérer via l'API"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: foundations
co_create: true
documentation_link: "../../../api/rest/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/244359
categories: [ System Access ]
level: secondary
---

Six améliorations sont désormais disponibles dans les API REST et GraphQL :

- Les requêtes de groupes acceptent `visibilityLevel` et `includeSubgroups`, et peuvent filtrer les groupes planifiés pour suppression avec `aimed_for_deletion`.
- L'API REST des merge requests accepte `merged_after` et `merged_before`.
- Les messages de récompense peuvent être modifiés après avoir été accordés, plutôt que d'être uniquement définis au moment de l'attribution.
- Les administrateurs peuvent réinitialiser les jetons SCIM via l'API de jeton d'administration.
- `CI_JOB_TOKEN` peut désormais récupérer les archives du dépôt, ce qui débloque les téléchargements de packages Composer privés qui avaient échoué lors de la dépréciation du fallback source.

Merci aux utilisateurs suivants pour leurs contributions !

- [Colin Jacob Boby](https://gitlab.com/jcb960) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249258))
- [nagraj raikar](https://gitlab.com/nraj0408) ([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/244359) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245378))
- [Niklas van Schrick](https://gitlab.com/Taucher2003) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246614))
- [Nicholas Wittstruck](https://gitlab.com/nwittstruck) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/243804))
- [Alessandro Lai](https://gitlab.com/Alessandro.Lai) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246159))
