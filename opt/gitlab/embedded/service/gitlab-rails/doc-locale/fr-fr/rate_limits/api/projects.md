---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Limitations du débit de l'API des projets"
description: "Définir des limites de débit sur les endpoints de l'API des projets."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!note]
> Lors de la mise à niveau vers GitLab 18.0 ou une version ultérieure, les limites de débit configurables pour cette API sont définies sur `0`. Les administrateurs peuvent ajuster les limites de débit selon leurs besoins. Pour en savoir plus sur les limites de débit concernées, consultez [Rate limitations announced for Projects, Groups, and Users APIs](https://about.gitlab.com/blog/rate-limitations-announced-for-projects-groups-and-users-apis/#rate-limitation-details).

## Configurer les limites de débit de l'API des projets {#configure-projects-api-rate-limits}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/421909) d'une limite de débit pour l'API des groupes et des projets dans GitLab 17.1 avec un [flag](../../administration/feature_flags/_index.md) nommé `rate_limit_groups_and_projects_api`. Désactivé par défaut. Fonctionnalité désactivée par défaut.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/461316) dans GitLab 18.1. Le feature flag `rate_limit_groups_and_projects_api` a été supprimé.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245318) d'une limite de débit sur la création de projets dans GitLab 19.3 avec un [flag](../../administration/feature_flags/_index.md) nommé `namespace_create_rate_limit`. Désactivé par défaut. Fonctionnalité désactivée par défaut.

{{< /history >}}

Configurez la limite de débit pour chaque adresse IP et utilisateur pour les requêtes vers les endpoints suivants de l'API des projets :

| Limite                                                                                                       | Valeur par défaut | Intervalle |
|-------------------------------------------------------------------------------------------------------------|---------|----------|
| [`GET /projects`](../../api/projects.md#list-all-projects) (requêtes non authentifiées)                       | 400     | 10 minutes |
| [`GET /projects`](../../api/projects.md#list-all-projects) (requêtes authentifiées)                         | 2000    | 10 minutes |
| [`GET /projects/:id`](../../api/projects.md#retrieve-a-project)                                             | 400     | 1 minute |
| [`GET /users/:user_id/projects`](../../api/projects.md#list-all-personal-projects-for-a-user)               | 300     | 1 minute |
| [`GET /users/:user_id/contributed_projects`](../../api/projects.md#list-all-projects-contributions-for-a-user) | 100     | 1 minute |
| [`GET /users/:user_id/starred_projects`](../../api/project_starring.md#list-projects-starred-by-a-user)     | 100     | 1 minute |
| [`POST /projects`](../../api/projects.md#create-a-project)                                                  | 200     | 1 jour |

Prérequis :

- Disposer d'un accès administrateur.

Pour modifier la limite de débit :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limitations du débit de l'API des projets**.
1. Modifiez la valeur d'une limite de débit, ou définissez une limite de débit sur `0` pour la désactiver.
1. Sélectionnez **Enregistrer les modifications**.

Les limites de débit :

- S'appliquent à chaque utilisateur authentifié. Si les requêtes ne sont pas authentifiées, les limites de débit s'appliquent à l'adresse IP.

Les requêtes dépassant la limite de débit sont consignées dans le fichier `auth.log`.

Par exemple, si vous définissez une limite de 400 pour `GET /projects/:id`, les requêtes vers l'endpoint de l'API qui dépassent un débit de 400 requêtes par minute sont bloquées. L'accès à l'endpoint est rétabli après une minute.

Pour en savoir plus sur les endpoints de l'API des projets, consultez l'[API des projets](../../api/projects.md#list-all-projects).

## Configurer les limites de débit sur la suppression des membres d'un projet {#configure-rate-limits-on-deleting-project-members}

Configurez la limite de débit pour chaque projet et utilisateur pour les requêtes vers l'[endpoint de suppression des membres](../../api/project_members.md#remove-a-direct-member-of-a-project).

Prérequis :

- Disposer d'un accès administrateur.

Pour modifier la limite de débit :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limite de débit de l'API des membres**.
1. Dans la zone de texte **Maximum de requêtes par minute et par groupe/projet**, saisissez une valeur.
1. Sélectionnez **Enregistrer les modifications**.

La limite de débit :

- Par défaut, 60 requêtes par minute
- S'applique à chaque projet et utilisateur.
- Peut être définie sur `0` pour désactiver la limite de débit.

Les requêtes dépassant la limite de débit sont consignées dans le fichier `auth.log`.

Par exemple, si vous définissez une limite de 60, les requêtes vers l'endpoint de l'API qui dépassent un débit de 60 requêtes par minute sont bloquées. L'accès à l'endpoint reprend après une minute.

## Configurer les limites de débit sur le listage des membres d'un projet {#configure-rate-limits-on-listing-project-members}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/578527) dans GitLab 18.6.

{{< /history >}}

Configurez la limite de débit pour les requêtes vers l'[endpoint de listage des membres d'un projet](../../api/project_members.md#list-all-members-of-a-project).

Les endpoints d'API `GET /projects/:id/members/all` et `GET /groups/:id/members/all` partagent la même configuration de limite de débit. Si vous définissez une limite de débit sur l'endpoint des projets, la limite de débit s'applique également à l'endpoint des groupes.

Prérequis :

- Disposer d'un accès administrateur.

Pour modifier la limite de débit :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limitations du débit de l'API des projets**.
1. Dans la zone de texte **Nombre maximum de requêtes vers l'API `GET /projects/:id/members/all` par minute et par utilisateur ou adresse IP**, saisissez une valeur.
1. Sélectionnez **Enregistrer les modifications**.

La limite de débit :

- Par défaut, 200 requêtes par minute.
- S'applique à chaque utilisateur authentifié. Si les requêtes ne sont pas authentifiées, la limite de débit s'applique à l'adresse IP.
- Peut être définie sur `0` pour désactiver les limites de débit.

Les requêtes dépassant la limite de débit sont consignées dans le fichier `auth.log`.

Par exemple, si vous définissez une limite de 200, les requêtes vers l'endpoint de l'API qui dépassent un débit de 200 requêtes par minute sont bloquées. L'accès à l'endpoint reprend après une minute.
