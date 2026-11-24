---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Contrôle d'accès aux GitLab Pages"
description: "Restreindre l'accès à un site GitLab Pages aux membres authentifiés du projet."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- La prise en charge du SSO SAML de groupe pour Pages a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/326288) dans GitLab 18.2 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `ff_oauth_redirect_to_sso_login`. Fonctionnalité désactivée par défaut.
- La prise en charge du SSO SAML de groupe pour les applications OAuth a été [activée sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200682) dans GitLab 18.3.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/561778) dans GitLab 18.5. Suppression du feature flag `ff_oauth_redirect_to_sso_login`.

{{< /history >}}

Vous pouvez activer le contrôle d'accès aux Pages pour votre projet si votre administrateur a [activé la fonctionnalité de contrôle d'accès](../../../administration/pages/_index.md#access-control) sur votre instance GitLab. Lorsqu'il est activé, seuls les [membres authentifiés de votre projet](../../permissions.md#project-permissions) (au moins Invité) peuvent accéder à votre site web par défaut :

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une démonstration, consultez [Pages access controls](https://www.youtube.com/watch?v=tSPAr5mQYc8).

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Visibilité, fonctionnalités du projet, autorisations**.
1. Pour activer le contrôle d'accès, activez le bouton **Pages**. Si vous ne voyez pas le bouton, cela signifie qu'il n'est pas activé. Demandez à votre administrateur de [l'activer](../../../administration/pages/_index.md#access-control).

1. Utilisez la liste déroulante de contrôle d'accès aux Pages pour définir qui peut consulter les pages hébergées avec GitLab Pages, en fonction de la visibilité de votre projet :

   - Si votre projet est privé :
     - **Membres du projet uniquement** : seuls les [membres du projet](../members/_index.md) peuvent parcourir le site web.
     - **Tout le monde** : tout le monde, qu'il soit connecté ou non à GitLab, peut parcourir le site web, quelle que soit son appartenance au projet.
   - Si votre projet est interne :
     - **Membres du projet uniquement** : seuls les membres du projet peuvent parcourir le site web.
     - **Toute personne ayant accès** : toute personne connectée à GitLab peut parcourir le site web, quelle que soit son appartenance au projet. Les [utilisateurs externes](../../../administration/external_users.md) peuvent accéder au site web uniquement s'ils sont membres du projet.
     - **Tout le monde** : tout le monde, qu'il soit connecté ou non à GitLab, peut parcourir le site web, quelle que soit son appartenance au projet.
   - Si votre projet est public :
     - **Membres du projet uniquement** : seuls les membres du projet peuvent parcourir le site web.
     - **Toute personne ayant accès** : tout le monde, qu'il soit connecté ou non à GitLab, peut parcourir le site web, quelle que soit son appartenance au projet.

1. Sélectionnez **Enregistrer les modifications**. Vos modifications peuvent ne pas prendre effet immédiatement. GitLab Pages utilise un mécanisme de mise en cache pour des raisons d'efficacité. Vos modifications peuvent ne pas prendre effet tant que ce cache n'est pas invalidé, ce qui prend généralement moins d'une minute.

La prochaine fois qu'une personne tente d'accéder à votre site web alors que le contrôle d'accès est activé, elle est invitée à se connecter à GitLab et à vérifier qu'elle peut accéder au site web.

Lorsque le [SSO SAML](../../group/saml_sso/_index.md) est configuré pour le groupe associé et que le contrôle d'accès est activé, les utilisateurs doivent s'authentifier via SSO avant d'accéder au site web.

Lorsque l'accès public est désactivé au niveau de l'[instance](../../../administration/pages/_index.md#disable-public-access-to-all-pages-sites) ou du [groupe](#remove-public-access-for-group-pages), les projets perdent l'option de niveau de visibilité **Tout le monde** et sont limités aux membres du projet ou à toute personne ayant accès, selon le paramètre de visibilité du projet.

## Supprimer l'accès public pour les Pages de groupe {#remove-public-access-for-group-pages}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/254962) dans GitLab 17.9.

{{< /history >}}

Configurez un paramètre pour le groupe afin de supprimer l'option de visibilité publique pour les Pages. Lorsque cette option est activée, tous les projets du groupe et de ses sous-groupes perdent la possibilité d'utiliser le niveau de visibilité « Tout le monde » et sont limités aux membres du projet ou à toute personne ayant accès, selon le paramètre de visibilité du projet.

Prérequis

- L'accès public aux Pages ne doit pas être [désactivé pour l'instance](../../../administration/pages/_index.md#disable-public-access-to-all-pages-sites).
- Vous devez avoir le rôle Propriétaire pour le groupe.

Pour cela :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Permissions et fonctionnalités du groupe**.
1. Sous **Accès public aux pages**, cochez la case **Supprimer l'accès public**.
1. Sélectionnez **Enregistrer les modifications**.

GitLab Pages utilise un cache pour des raisons d'efficacité. Les modifications apportées aux paramètres d'accès prennent généralement effet en une minute lors de la mise à jour du cache.

## S'authentifier avec un jeton d'accès {#authenticate-with-an-access-token}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab-pages/-/issues/388) dans GitLab 17.10.

{{< /history >}}

Pour vous authentifier auprès d'un site GitLab Pages à accès restreint, vous pouvez fournir l'en-tête `Authorization` avec un jeton d'accès.

Prérequis :

- Vous devez disposer de l'un des jetons d'accès suivants avec la portée `read_api` :
  - [Jeton d'accès personnel](../../profile/personal_access_tokens.md#create-a-personal-access-token)
  - [Jeton d'accès au projet](../settings/project_access_tokens.md#create-a-project-access-token)
  - [Jeton d'accès de groupe](../../group/settings/group_access_tokens.md#create-a-group-access-token)
  - [Jeton OAuth 2.0](../../../api/oauth2.md)

Par exemple, pour utiliser un jeton d'accès avec des en-têtes conformes OAuth :

```shell
curl --header "Authorization: Bearer <your_access_token>" <published_pages_url>
```

Pour les jetons d'accès invalides ou non autorisés, renvoie [`404`](../../../api/rest/troubleshooting.md#status-codes).

## Terminer une session Pages {#terminating-a-pages-session}

Pour vous déconnecter de votre site web GitLab Pages, révoquez le jeton d'accès de l'application pour GitLab Pages :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Applications**.
1. Dans la section **Applications autorisées**, trouvez l'entrée **GitLab Pages** et sélectionnez **Révoquer**.
