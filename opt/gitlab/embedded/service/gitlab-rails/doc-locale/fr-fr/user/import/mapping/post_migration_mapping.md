---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Mappage des contributions et des appartenances après migration
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/443557) dans GitLab 17.4 pour le transfert direct [avec des feature flags](../../../administration/feature_flags/_index.md) nommés `importer_user_mapping` et `bulk_import_importer_user_mapping`. Fonctionnalité désactivée par défaut.
- Introduit dans GitLab 17.6 pour [Gitea](https://gitlab.com/gitlab-org/gitlab/-/issues/467084) [avec des feature flags](../../../administration/feature_flags/_index.md) nommés `importer_user_mapping` et `gitea_user_mapping`, et pour [GitHub](https://gitlab.com/gitlab-org/gitlab/-/issues/466355) avec des flags nommés `importer_user_mapping` et `github_user_mapping`. Fonctionnalité désactivée par défaut.
- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/466356) dans GitLab 17.7 pour Bitbucket Server [avec des feature flags](../../../administration/feature_flags/_index.md) nommés `importer_user_mapping` et `bitbucket_server_user_mapping`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com et GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/issues/472735) dans GitLab 17.7 pour le transfert direct.
- Activé sur GitLab.com dans GitLab 17.7 pour [Bitbucket Server](https://gitlab.com/gitlab-org/gitlab/-/issues/509897), [Gitea](https://gitlab.com/gitlab-org/gitlab/-/issues/498390) et [GitHub](https://gitlab.com/gitlab-org/gitlab/-/issues/499993).
- Activé sur GitLab Self-Managed dans GitLab 17.8 pour [Bitbucket Server](https://gitlab.com/gitlab-org/gitlab/-/issues/509897), [Gitea](https://gitlab.com/gitlab-org/gitlab/-/issues/498390) et [GitHub](https://gitlab.com/gitlab-org/gitlab/-/issues/499993).
- La réattribution des contributions au propriétaire d'un espace de nommage personnel lors d'une importation vers un espace de nommage personnel a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/525342) dans GitLab 18.3 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `user_mapping_to_personal_namespace_owner`. Fonctionnalité désactivée par défaut.
- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/508945) dans GitLab 18.4 pour le transfert direct. Le feature flag `bulk_import_importer_user_mapping` a été supprimé.
- La réattribution des contributions aux comptes de service, aux bots de projet et aux bots de groupe a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/573124) dans GitLab 18.5 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `user_mapping_service_account_and_bots`. Activés par défaut.
- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/512211) dans GitLab 18.6 pour Gitea. Le feature flag `gitea_user_mapping` a été supprimé.
- La réattribution des contributions au propriétaire d'un espace de nommage personnel lors d'une importation vers un espace de nommage personnel est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/211626) dans GitLab 18.6. Le feature flag `user_mapping_to_personal_namespace_owner` a été supprimé.
- Le feature flag `github_user_mapping` a été [supprimé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/216778) dans GitLab 18.8.
- Le feature flag `user_mapping_service_account_and_bots` a été [supprimé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/223142) dans GitLab 18.10.

{{< /history >}}

Avec le mappage après migration, les contributions et les appartenances des utilisateurs provenant des instances sources sont initialement attribuées à des utilisateurs d'espace réservé plutôt qu'à de véritables utilisateurs sur l'instance de destination.

Étant donné que vous pouvez différer l'attribution aux véritables utilisateurs, vous disposez du temps nécessaire pour examiner l'importation et réattribuer les contributions aux utilisateurs appropriés. Ce processus garantit une attribution précise tout en maintenant le contrôle sur le processus de mappage.

Le mappage des contributions et des appartenances des utilisateurs après migration est disponible par défaut pour les migrations depuis :

- [GitLab lors de l'utilisation du transfert direct](../../group/import/_index.md)
- [GitHub](../../project/import/github.md)
- [Bitbucket Server](../bitbucket_server.md)
- [Gitea](../gitea.md)

Lorsque vous importez des projets vers un [espace de nommage personnel](../../namespace/_index.md#types-of-namespaces), le mappage des contributions et des appartenances des utilisateurs n'est pas pris en charge et toutes les contributions sont attribuées au propriétaire de l'espace de nommage personnel. Ces contributions ne peuvent pas être réattribuées.

## Prérequis {#prerequisites}

- Planifiez le nombre d'utilisateurs en fonction des [limites d'utilisateurs](#placeholder-user-limits).
- Si vous importez vers GitLab.com, configurez votre espace de nommage payant.
- Si vous importez vers GitLab.com et utilisez [SAML SSO pour les groupes GitLab.com](../../group/saml_sso/_index.md), assurez-vous que tous les utilisateurs associent leur identité SAML à leur compte GitLab.com.

## Workflow de mappage après migration {#post-migration-mapping-workflow}

Lors de l'utilisation du mappage après migration, GitLab mappe les appartenances et les contributions que vous importez vers des [utilisateurs d'espace réservé](#placeholder-users). Les utilisateurs d'espace réservé sont créés sur l'instance de destination, même si des utilisateurs avec les mêmes adresses e-mail existent déjà sur l'instance de destination. Tant que vous ne réattribuez pas les contributions sur l'instance de destination, toutes les contributions sont associées à des utilisateurs d'espace réservé.

Une fois l'importation terminée et les résultats examinés, vous pouvez mettre à jour les mappages comme suit :

- Réattribuez les appartenances et les contributions aux utilisateurs existants sur l'instance de destination. Vous pouvez mapper les appartenances et les contributions pour des utilisateurs ayant des adresses e-mail différentes sur les instances source et de destination.
- Créez de nouveaux utilisateurs sur l'instance de destination et réattribuez-leur les appartenances et les contributions.

Vous pouvez également conserver certaines contributions attribuées à des utilisateurs d'espace réservé afin de préserver le contexte historique.

Lorsque vous réattribuez des contributions à un utilisateur sur l'instance de destination, l'utilisateur peut soit :

- Accepter la réattribution. Le processus de réattribution peut prendre quelques minutes. Dans les importations ultérieures depuis la même instance source vers le même groupe principal ou sous-groupe sur l'instance de destination, les contributions sont mappées automatiquement à l'utilisateur.
- Refuser la réattribution.

## Utilisateurs Enterprise {#enterprise-users}

{{< history >}}

- [Introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/510673) dans GitLab 18.0.

{{< /history >}}

Si votre groupe principal compte au moins un [utilisateur Enterprise](../../enterprise_user/_index.md), vous ne pouvez réattribuer les contributions qu'aux utilisateurs Enterprise de votre organisation.

Cela signifie que vous ne pouvez pas réattribuer accidentellement des contributions à des utilisateurs extérieurs à votre organisation.

## Utilisateurs supprimés {#deleted-users}

Les contributions sur l'instance source effectuées par un utilisateur désormais supprimé sont mappées sur l'instance de destination vers [un utilisateur fantôme](../../../administration/internal_users.md), sauf dans les cas suivants :

- La contribution n'a jamais été correctement dissociée de l'utilisateur supprimé sur l'instance source.
- Migration depuis Bitbucket Server.

## Utilisateurs d'espace réservé {#placeholder-users}

Avec le mappage des contributions et des appartenances, vous n'attribuez pas immédiatement les contributions et les appartenances aux utilisateurs sur l'instance de destination. Un utilisateur d'espace réservé est créé pour tout utilisateur actif, inactif ou bot disposant de contributions ou d'appartenances importées.

Les contributions et les appartenances sont initialement attribuées à ces utilisateurs d'espace réservé et peuvent être réattribuées après l'importation aux utilisateurs existants sur l'instance de destination.

Tant qu'elles ne sont pas réattribuées, les contributions sont associées à l'espace réservé. Les appartenances d'espace réservé ne s'affichent pas dans les listes de membres.

Les utilisateurs d'espace réservé ne sont pas comptabilisés dans les limites de licence.

### Exceptions {#exceptions}

Un utilisateur d'espace réservé n'est pas créé dans les scénarios suivants :

- Vous importez un projet depuis [Gitea](../gitea.md) avec des contributions d'utilisateurs supprimés. Les contributions de ces utilisateurs sont mappées à l'utilisateur qui a importé le projet.
- Vous avez dépassé votre [limite d'utilisateurs d'espace réservé](#placeholder-user-limits). Les contributions de tout nouvel utilisateur sont mappées à un utilisateur d'importation.

### Attributs des utilisateurs d'espace réservé {#placeholder-user-attributes}

Les utilisateurs d'espace réservé sont différents des utilisateurs ordinaires et ne peuvent pas :

- Se connecter.
- Effectuer des actions. Par exemple, exécuter des pipelines.
- Apparaître dans les suggestions en tant que responsables ou relecteurs pour les tickets et les merge requests.
- Être membres de projets et de groupes.

Pour maintenir un lien avec un utilisateur sur une instance source, les utilisateurs d'espace réservé disposent des éléments suivants :

- Un identifiant unique (`source_user_id`) utilisé par le processus d'importation pour déterminer si un nouvel utilisateur d'espace réservé est nécessaire.
- Un nom d'hôte ou un domaine source (`source_hostname`).
- Le nom de l'utilisateur source (`source_name`) pour faciliter la réattribution des contributions.
- Le nom d'utilisateur de l'utilisateur source (`source_username`) pour faciliter la tâche des propriétaires de groupes lors de la réattribution des contributions.
- Un type d'importation (`import_type`) permettant de distinguer quel importateur a créé l'espace réservé.
- Un horodatage de création de l'utilisateur source (`created_at`) en heure locale à des fins de suivi de la migration ([introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/507297) dans GitLab 17.10).

Pour préserver le contexte historique, le nom et le nom d'utilisateur de l'utilisateur d'espace réservé sont dérivés du nom et du nom d'utilisateur de l'utilisateur source :

- Le nom de l'utilisateur d'espace réservé est `Placeholder <source user name>`.
- Le nom d'utilisateur de l'utilisateur d'espace réservé est `%{source_username}_placeholder_user_%{incremental_number}`.

### Afficher les utilisateurs d'espace réservé {#view-placeholder-users}

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.

Les utilisateurs d'espace réservé sont créés sur l'instance de destination lors de l'importation d'un groupe ou d'un projet. Pour afficher les utilisateurs d'espace réservé créés lors des importations vers un groupe principal et ses sous-groupes :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe. Ce groupe doit se trouver au niveau principal.
1. Dans la barre latérale gauche, sélectionnez **Gérer** > **Membres**.
1. Sélectionnez l'onglet **Espaces réservés**.

### Filtrer les utilisateurs d'espace réservé {#filter-for-placeholder-users}

{{< details >}}

- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/521974) dans GitLab 17.11.

{{< /history >}}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

Les utilisateurs d'espace réservé sont créés sur l'instance de destination lors de l'importation d'un groupe ou d'un projet. Pour filtrer les utilisateurs d'espace réservé créés lors des importations pour toute une instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Vue d'ensemble** > **Utilisateurs**.
1. Dans la zone de recherche, filtrez les utilisateurs par **type**.

### Création d'utilisateurs d'espace réservé {#creating-placeholder-users}

Les utilisateurs d'espace réservé sont créés par source d'importation et par groupe principal :

- Si vous importez le même projet deux fois vers le même groupe principal sur l'instance de destination, la deuxième importation utilise les mêmes utilisateurs d'espace réservé que la première importation.
- Si vous importez le même projet deux fois, mais vers un groupe principal différent sur l'instance de destination, la deuxième importation crée de nouveaux utilisateurs d'espace réservé sous ce groupe principal.

> [!note]
> Les utilisateurs d'espace réservé sont associés uniquement au groupe principal. Lorsque vous supprimez un sous-groupe ou un projet, leurs utilisateurs d'espace réservé ne font plus référence à aucune contribution dans le groupe principal. Pour les tests, vous devez utiliser un groupe principal dédié. La suppression des utilisateurs d'espace réservé est proposée dans [l'issue 519391](https://gitlab.com/gitlab-org/gitlab/-/issues/519391) et [l'issue 537340](https://gitlab.com/gitlab-org/gitlab/-/issues/537340).

Lorsqu'un utilisateur [accepte la réattribution](reassignment.md#accept-contribution-reassignment), les importations ultérieures depuis la même instance source vers le même groupe principal ou sous-groupe sur l'instance de destination ne créent pas d'utilisateurs d'espace réservé. Les contributions sont plutôt mappées automatiquement à l'utilisateur.

### Suppression des utilisateurs d'espace réservé {#placeholder-user-deletion}

{{< history >}}

- [Introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/473256) dans GitLab 18.0.

{{< /history >}}

Lorsque vous supprimez un groupe principal contenant des utilisateurs d'espace réservé, ces utilisateurs sont automatiquement planifiés pour suppression. Ce processus peut prendre un certain temps. Cependant, les utilisateurs d'espace réservé restent dans le système s'ils sont également associés à d'autres projets ou groupes.

> [!note]
> Il n'existe pas d'autre moyen de supprimer les utilisateurs d'espace réservé, mais la prise en charge d'améliorations est proposée dans [l'issue 519391](https://gitlab.com/gitlab-org/gitlab/-/issues/519391) et [l'issue 537340](https://gitlab.com/gitlab-org/gitlab/-/issues/537340).

### Limites des utilisateurs d'espace réservé {#placeholder-user-limits}

En cas d'importation vers GitLab.com, les utilisateurs d'espace réservé sont limités par groupe principal sur l'instance de destination. Les limites varient en fonction de votre plan et du nombre de sièges. Les utilisateurs d'espace réservé ne sont pas comptabilisés dans les limites de licence.

| Plan GitLab.com          | Nombre de sièges | Limite d'utilisateurs d'espace réservé sur le groupe principal |
|:-------------------------|:----------------|:------------------------------------------|
| Gratuite et tout essai       | Tout montant      | 200                                       |
| GitLab Premium                  | < 100           | 500                                       |
| GitLab Premium                  | 101-500         | 2 000                                     |
| GitLab Premium                  | 501 - 1000      | 4 000                                     |
| GitLab Premium                  | > 1000          | 6 000                                      |
| Ultimate et open source | < 100           | 1 000                                      |
| Ultimate et open source | 101-500         | 4 000                                     |
| Ultimate et open source | 501 - 1000      | 6 000                                      |
| Ultimate et open source | > 1000          | 8 000                                     |

Pour GitLab Self-Managed et GitLab Dedicated, aucune limite d'espace réservé ne s'applique par défaut. Un administrateur GitLab peut [définir une limite d'espace réservé](../../../administration/instance_limits.md#import-placeholder-user-limits) sur son instance.

Pour afficher votre utilisation actuelle et vos limites d'utilisateurs d'espace réservé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe. Ce groupe doit se trouver au niveau principal.
1. Sélectionnez **Paramètres** > **Quotas d'utilisation**.
1. Sélectionnez l'onglet **Importer**.

Vous ne pouvez pas déterminer à l'avance le nombre d'utilisateurs d'espace réservé dont vous avez besoin.

Lorsque la limite d'utilisateurs d'espace réservé est atteinte, toutes les contributions sont attribuées à un unique utilisateur non fonctionnel appelé `Import User`. Les contributions attribuées à `Import User` peuvent être dédupliquées, et certaines contributions peuvent ne pas être créées lors de l'importation. Par exemple, si plusieurs approbations d'un approbateur de merge request sont attribuées à `Import User`, seule la première approbation est créée et les autres sont ignorées. Les contributions susceptibles d'être dédupliquées sont :

- Règles d'approbation
- Réactions emoji
- Responsables de tickets
- Appartenances
- Approbations, responsables et relecteurs de merge requests
- Niveaux d'accès en push, merge request et déploiement

Chaque modification crée une note système, qui n'est pas affectée par la limite d'utilisateurs d'espace réservé.

## Méthode de mappage alternative {#alternative-mapping-method}

Une alternative au mappage après migration est une méthode qui effectue le mappage pendant la migration. Cette méthode n'est pas recommandée et les problèmes éventuellement rencontrés sont peu susceptibles d'être corrigés.

La méthode de mappage alternative :

- Est disponible uniquement pour les migrations vers GitLab Self-Managed.
- Nécessite une préparation avant la migration, notamment la désactivation des feature flags `*_user_mapping` applicables.
- Est disponible pour les migrations depuis :
  - GitHub.
  - Bitbucket Server.
  - Gitea (pour GitLab 18.5 et versions antérieures).

Pour plus d'informations, consultez la documentation sur la méthode de mappage alternative pour chaque importateur.
