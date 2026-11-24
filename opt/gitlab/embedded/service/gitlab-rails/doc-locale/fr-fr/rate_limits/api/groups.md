---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Limites de débit de l'API des groupes"
description: "Définir des limites de débit sur les endpoints de l'API des groupes."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!note]
> Lors de la mise à niveau vers GitLab 18.0 ou une version ultérieure, les limites de débit configurables pour cette API sont définies sur `0`. Les administrateurs peuvent ajuster les limites de débit selon leurs besoins. Pour savoir quelles limites de débit sont concernées, consultez [Annonce des limites de fréquence pour les API des projets, des groupes et des utilisateurs](https://about.gitlab.com/blog/rate-limitations-announced-for-projects-groups-and-users-apis/#rate-limitation-details).

## Configurer les limites de débit de l'API des groupes {#configure-groups-api-rate-limits}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/152733) de la limite de débit pour l'API des groupes et des projets dans GitLab 17.1 avec un [flag](../../administration/feature_flags/_index.md) nommé `rate_limit_groups_and_projects_api`. Désactivé par défaut. Fonctionnalité désactivée par défaut.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/461316) dans GitLab 18.1. Le feature flag `rate_limit_groups_and_projects_api` a été supprimé.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245318) d'une limite de débit sur la création de groupes dans GitLab 19.3 avec un [flag](../../administration/feature_flags/_index.md) nommé `namespace_create_rate_limit`. Désactivé par défaut. Fonctionnalité désactivée par défaut.

{{< /history >}}

Configurez la limite de débit pour chaque adresse IP et chaque utilisateur pour les requêtes vers les endpoints suivants de l'API des groupes :

| Limite                                                           | Valeur par défaut | Intervalle |
|-----------------------------------------------------------------|---------|----------|
| [`GET /groups`](../../api/groups.md#list-groups)                | 200     | 1 minute |
| [`GET /groups/:id`](../../api/groups.md#retrieve-a-group)     | 400     | 1 minute |
| [`GET /groups/:id/groups/shared`](../../api/groups.md#list-shared-groups) | 60    | 1 minute |
| [`GET /groups/:id/invited_groups`](../../api/groups.md#list-shared-groups) | 60     | 1 minute |
| [`GET /groups/:id/projects`](../../api/groups.md#list-projects) | 600     | 1 minute |
| [`POST /groups/:id/archive`](../../api/groups.md#archive-a-group) | 60    | 1 minute |
| [`POST /groups`](../../api/groups.md#create-a-group)            | 200     | 1 jour |

Prérequis :

- Disposer d'un accès administrateur.

Pour modifier la limite de débit :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limites de débit de l'API des groupes**.
1. Modifiez la valeur de n'importe quelle limite de débit, ou définissez une limite de débit à `0` pour la désactiver.
1. Sélectionnez **Enregistrer les modifications**.

Les limites de débit :

- S'appliquent à chaque utilisateur authentifié. Si les requêtes ne sont pas authentifiées, les limites de débit s'appliquent à l'adresse IP.
- Peuvent être définies à 0 pour désactiver la limitation de débit.

Les requêtes dépassant la limite de débit sont consignées dans le fichier `auth.log`.

Par exemple, si vous définissez une limite de 400 pour `GET /groups/:id`, les requêtes vers l'endpoint de l'API qui dépassent un débit de 400 par minute sont bloquées. L'accès à l'endpoint est rétabli après une minute.

## Limite de débit sur le listage des membres des groupes et des projets {#rate-limit-on-listing-group-and-project-members}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/578527) dans GitLab 18.6.

{{< /history >}}

Une limite de débit est définie sur l'[endpoint de l'API listant tous les membres d'un groupe](../../api/group_members.md#list-all-group-members-including-inherited-and-invited-members).

Les endpoints d'API `GET /projects/:id/members/all` et `GET /groups/:id/members/all` partagent la même configuration de limite de débit. Si vous définissez une limite de débit sur l'endpoint des projets, la limite de débit s'applique également à l'endpoint des groupes.

Prérequis :

- Disposer d'un accès administrateur.

Pour modifier cette limite de débit pour les deux endpoints :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limitations du débit de l'API des projets**.
1. Dans la zone de texte **Nombre maximum de requêtes vers l'API `GET /projects/:id/members/all` par minute et par utilisateur ou adresse IP**, saisissez une valeur.
1. Sélectionnez **Enregistrer les modifications**.

La limite de débit :

- Est définie par défaut à 200 requêtes par minute.
- S'applique à chaque utilisateur authentifié. Si les requêtes ne sont pas authentifiées, la limite de débit s'applique à l'adresse IP.
- Est configurée via les paramètres de limitations du débit de l'API des projets. Pour plus d'informations, consultez [Configurer les limites de débit sur le listage des membres d'un projet](projects.md#configure-rate-limits-on-listing-project-members).
- Peut être définie à `0` pour désactiver la limite de débit pour les deux endpoints.

Les requêtes dépassant la limite de débit sont consignées dans le fichier `auth.log`.

Par exemple, les requêtes vers l'endpoint de l'API qui dépassent un débit de 200 requêtes par minute sont bloquées. L'accès à l'endpoint reprend après une minute.

## Configurer les limites de débit sur l'archivage et le désarchivage des groupes {#configure-rate-limits-on-group-archiving-and-unarchiving}

{{< details >}}

- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/481969) dans GitLab 18.0 [avec le feature flag](../../administration/feature_flags/_index.md) `archive_group`. Fonctionnalité désactivée par défaut.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/526771) dans GitLab 18.9. Le feature flag `archive_group` a été supprimé.

{{< /history >}}

Configurez une limite de débit sur les requêtes vers les endpoints d'archivage de groupes suivants :

```plaintext
POST /groups/:id/archive
POST /groups/:id/unarchive
```

Prérequis :

- Disposer d'un accès administrateur.

Pour modifier la limite de débit :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limites de débit de l'API des groupes**.
1. Dans la zone de texte **Nombre maximum de requêtes vers les API `POST /groups/:id/archive` et `POST /groups/:id/unarchive` par minute et par utilisateur ou adresse IP**, saisissez une valeur.
1. Sélectionnez **Enregistrer les modifications**.

La limite de débit :

- Est définie par défaut à 60 requêtes par minute
- S'applique à chaque utilisateur authentifié. Si les requêtes ne sont pas authentifiées, les limites de débit s'appliquent à l'adresse IP.
- Peut être définie à `0` pour désactiver les limites de débit pour les deux endpoints

Les requêtes dépassant la limite de débit sont consignées dans le fichier `auth.log`.

Par exemple, si vous définissez une limite de 60, les requêtes vers l'endpoint de l'API qui dépassent un débit de 60 requêtes par minute sont bloquées. L'accès à l'endpoint reprend après une minute.

Pour plus d'informations sur les endpoints d'archivage de groupes, consultez [Archiver un groupe](../../api/groups.md#archive-a-group).

## Configurer les limites de débit sur la suppression des membres d'un groupe {#configure-rate-limits-on-deleting-group-members}

Configurez la limite de débit pour chaque groupe et chaque utilisateur pour les requêtes vers l'[endpoint de suppression des membres](../../api/group_members.md#remove-a-group-member).

Prérequis :

- Disposer d'un accès administrateur.

Pour modifier la limite de débit :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limite de débit de l'API des membres**.
1. Dans la zone de texte **Maximum de requêtes par minute et par groupe/projet**, saisissez une valeur.
1. Sélectionnez **Enregistrer les modifications**.

La limite de débit :

- Est définie par défaut à 60 requêtes par minute.
- S'applique pour chaque groupe et chaque utilisateur.
- Peut être définie à `0` pour désactiver la limite de débit.

Les requêtes dépassant la limite de débit sont consignées dans le fichier `auth.log`.

Par exemple, si vous définissez une limite de 60, les requêtes vers l'endpoint de l'API qui dépassent un débit de 60 requêtes par minute sont bloquées. L'accès à l'endpoint est rétabli après une minute.
