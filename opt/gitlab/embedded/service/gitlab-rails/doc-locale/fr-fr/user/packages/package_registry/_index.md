---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Registre de paquets
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Déplacé](https://gitlab.com/gitlab-org/gitlab/-/issues/221259) de GitLab Premium vers GitLab Free dans la version 13.3.

{{< /history >}}

Avec le registre de paquets GitLab, vous pouvez utiliser GitLab comme registre privé ou public pour une variété de [gestionnaires de paquets pris en charge](supported_functionality.md). Vous pouvez publier et partager des paquets, qui peuvent être utilisés comme dépendance dans des projets en aval.

## Workflows de paquets {#package-workflows}

Découvrez comment utiliser le registre de paquets GitLab pour créer votre propre workflow de paquets personnalisé :

- [Utiliser un projet comme registre de paquets](../workflows/project_registry.md) pour publier tous vos paquets dans un seul projet.

- Publiez plusieurs paquets différents depuis un seul [projet monorepo](../workflows/working_with_monorepos.md).

## Afficher les paquets {#view-packages}

Vous pouvez afficher les paquets de votre projet ou groupe :

1. Accédez au projet ou au groupe.
1. Accédez à **Déployer** > **Registre de paquets**.

Vous pouvez rechercher, trier et filtrer les paquets sur cette page. Vous pouvez partager vos résultats de recherche en copiant et collant l'URL depuis votre navigateur.

Vous pouvez également trouver des extraits de code utiles pour configurer votre gestionnaire de paquets ou installer un paquet donné.

Lorsque vous affichez des paquets dans un groupe :

- Tous les paquets publiés dans le groupe et ses projets sont affichés.
- Seuls les projets auxquels vous avez accès sont affichés.
- Si un projet est privé ou si vous n'êtes pas membre du projet, les paquets de ce projet ne sont pas affichés.

Pour savoir comment créer et charger un paquet, suivez les instructions correspondant à votre [type de paquet](supported_functionality.md).

## Utiliser GitLab CI/CD {#use-gitlab-cicd}

Vous pouvez utiliser [GitLab CI/CD](../../../ci/_index.md) pour compiler ou importer des paquets dans un registre de paquets.

### Pour compiler des paquets {#to-build-packages}

Vous pouvez vous authentifier auprès de GitLab en utilisant le `CI_JOB_TOKEN`.

Pour commencer, vous pouvez utiliser les [modèles CI/CD](https://gitlab.com/gitlab-org/gitlab/-/tree/master/lib/gitlab/ci/templates) disponibles.

Pour plus d'informations sur l'utilisation du registre de paquets GitLab avec CI/CD, consultez :

- [Générique](../generic_packages/_index.md#publish-a-package)
- [Maven](../maven_repository/_index.md#create-maven-packages-with-gitlab-cicd)
- [npm](../npm_registry/_index.md#publish-a-package-with-a-cicd-pipeline)
- [NuGet](../nuget_repository/_index.md#with-a-cicd-pipeline)
- [PyPI](../pypi_repository/_index.md#authenticate-with-the-gitlab-package-registry)
- [Terraform](../terraform_module_registry/_index.md#authenticate-to-the-terraform-module-registry)

Si vous utilisez CI/CD pour compiler un paquet, des informations d'activité étendues sont affichées lorsque vous consultez les détails du paquet :

![Activité CI/CD du paquet](img/package_activity_v12_10.png)

Vous pouvez voir quel pipeline a publié le paquet, ainsi que le commit et l'utilisateur qui l'ont déclenché. Cependant, l'historique est limité à cinq mises à jour d'un paquet donné.

### Pour importer des paquets {#to-import-packages}

Si vous disposez déjà de paquets compilés dans un autre registre, vous pouvez les importer dans votre registre de paquets GitLab à l'aide de l'[importateur de paquets](https://gitlab.com/gitlab-org/ci-cd/package-stage/pkgs_importer).

Pour obtenir la liste des paquets pris en charge, consultez [Importation de paquets depuis d'autres dépôts](supported_functionality.md#importing-packages-from-other-repositories).

## Réduire l'utilisation du stockage {#reduce-storage-usage}

Pour plus d'informations sur la réduction de votre utilisation du stockage pour le registre de paquets, consultez [Réduire l'utilisation du stockage du registre de paquets](reduce_package_registry_storage.md).

## Désactiver le registre de paquets {#turn-off-the-package-registry}

Le registre de paquets est automatiquement activé.

Sur une instance GitLab Self-Managed, votre administrateur peut supprimer l'élément de menu **Paquets et registres** de la barre latérale GitLab. Pour plus d'informations, consultez [Administration du registre de paquets GitLab](../../../administration/packages/_index.md).

Vous pouvez également supprimer le registre de paquets spécifiquement pour votre projet :

1. Dans votre projet, accédez à **Paramètres** > **Général**.
1. Développez la section **Visibilité, fonctionnalités du projet, autorisations** et désactivez la fonctionnalité **Paquet**.
1. Sélectionnez **Enregistrer les modifications**.

L'entrée **Déployer** > **Registre de paquets** est supprimée de la barre latérale.

## Autorisations de visibilité du registre de paquets {#package-registry-visibility-permissions}

[Les autorisations du projet](../../permissions.md) déterminent quels membres et utilisateurs peuvent télécharger, envoyer ou supprimer des paquets.

La visibilité du registre de paquets est indépendante du dépôt et peut être contrôlée depuis les paramètres de votre projet. Par exemple, si vous avez un projet public et que vous définissez la visibilité du dépôt sur **Uniquement les membres du projet**, le registre de paquets est alors public. La désactivation du bouton **Registre de paquets** désactive toutes les opérations du registre de paquets.

| Visibilité des projets | Action                | [Rôle](../../permissions.md#roles) minimum requis     |
|--------------------|-----------------------|---------------------------------------------------------|
| Public             | Afficher le registre de paquets | S/O. Toute personne sur Internet peut effectuer cette action.    |
| Public             | Publier un paquet     | Développeur                                               |
| Public             | Extraire un paquet        | S/O. Toute personne sur Internet peut effectuer cette action.    |
| Interne           | Afficher le registre de paquets | Invité                                                   |
| Interne           | Publier un paquet     | Développeur                                               |
| Interne           | Extraire un paquet        | Invité (1)                                               |
| Privé            | Afficher le registre de paquets | Rapporteur                                                |
| Privé            | Publier un paquet     | Développeur                                               |
| Privé            | Extraire un paquet        | Rapporteur (1)                                            |

### Autoriser tout le monde à puiser dans le registre des paquets {#allow-anyone-to-pull-from-package-registry}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/385994) dans GitLab 15.7.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/468058) dans GitLab 17.4 pour prendre en charge les points de terminaison de groupe NuGet.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/468059) dans GitLab 17.5 pour prendre en charge le point de terminaison de groupe Maven.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/468062) dans GitLab 17.5 pour prendre en charge les points de terminaison d'espace de nommage du module Terraform.

{{< /history >}}

Pour autoriser tout le monde à extraire des paquets depuis le registre de paquets, quelle que soit la visibilité du projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre projet privé ou interne.
1. Sélectionnez **Paramètres** > **Généralités**.
1. Développez **Visibilité, fonctionnalités du projet, autorisations**.
1. Activez le bouton **Autoriser tout le monde à puiser dans le registre des paquets**.
1. Sélectionnez **Enregistrer les modifications**.

Toute personne sur Internet peut accéder au registre de paquets du projet.

#### Désactiver l'autorisation d'extraction pour tous {#disable-allowing-anyone-to-pull}

Prérequis :

- Vous devez être administrateur.

Pour masquer globalement le bouton **Autoriser tout le monde à puiser dans le registre des paquets** :

- [Mettez à jour le paramètre d'application](../../../api/settings.md#update-application-settings) `package_registry_allow_anyone_to_pull_option` avec la valeur `false`.

Les téléchargements anonymes sont désactivés, même pour les projets pour lesquels le bouton **Autoriser tout le monde à puiser dans le registre des paquets** est activé.

Plusieurs problèmes connus existent lorsque vous autorisez tout le monde à extraire des paquets depuis le registre de paquets :

- Les points de terminaison pour les projets sont pris en charge.
- Les points de terminaison du registre NuGet pour les groupes sont pris en charge. Cependant, en raison de la façon dont les clients NuGet envoient les informations d'authentification, les téléchargements anonymes ne sont pas autorisés. Seuls les utilisateurs GitLab peuvent extraire des paquets depuis le registre de paquets, même si ce paramètre est activé.
- Les points de terminaison du registre Maven pour les groupes sont pris en charge.
- Les points de terminaison du registre de modules Terraform pour les espaces de nommage sont pris en charge.
- Les autres points de terminaison de groupe et d'instance ne sont pas entièrement pris en charge. La prise en charge des points de terminaison de groupe est proposée dans l'[epic 14234](https://gitlab.com/groups/gitlab-org/-/epics/14234).
- Cette fonctionnalité ne fonctionne pas avec [Composer](../composer_repository/_index.md#install-a-composer-package), car Composer ne dispose que d'un point de terminaison de groupe.
- Cette fonctionnalité fonctionne avec Conan, mais l'utilisation de [`conan search`](../conan_1_repository/_index.md#search-for-conan-packages-in-the-package-registry) ne fonctionne pas.

## Événements d'audit {#audit-events}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/329588) dans GitLab 17.10 [avec le feature flag](../../../administration/feature_flags/_index.md) `package_registry_audit_events`. Fonctionnalité désactivée par défaut.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/554817) dans GitLab 18.2. Le feature flag `package_registry_audit_events` a été supprimé.

{{< /history >}}

Créez des événements d'audit lorsqu'un paquet est publié ou supprimé. Les propriétaires d'espace de nommage peuvent activer le paramètre `audit_events_enabled` via l'[API GraphQL](../../../api/graphql/reference/_index.md#packagesettings).

Vous pouvez consulter les événements d'audit :

- Sur la page [**Événements d'audit de groupe**](../../compliance/audit_events.md#group-audit-events) si le projet du paquet se trouve dans un groupe.
- Sur la page [**Événements d'audit de projet**](../../compliance/audit_events.md#project-audit-events) si le projet du paquet se trouve dans un espace de nommage utilisateur.

## Contributions acceptées {#accepting-contributions}

Le tableau suivant répertorie les formats de paquets qui ne sont pas pris en charge. Envisagez de contribuer à GitLab pour ajouter la prise en charge de ces formats.

<!-- vale gitlab_base.Spelling = NO -->

| Format    | Statut                                                        |
| --------- | ------------------------------------------------------------- |
| Conda     | [\#36891](https://gitlab.com/gitlab-org/gitlab/-/issues/36891) |
| CRAN      | [\#36892](https://gitlab.com/gitlab-org/gitlab/-/issues/36892) |
| RPM       | [\#5932](https://gitlab.com/groups/gitlab-org/-/epics/5128)    |
| Swift     | [\#12233](https://gitlab.com/gitlab-org/gitlab/-/issues/12233) |

<!-- vale gitlab_base.Spelling = YES -->
