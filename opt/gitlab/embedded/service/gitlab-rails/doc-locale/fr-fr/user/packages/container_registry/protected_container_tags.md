---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Étiquettes de conteneurs protégées
description: Contrôlez qui peut pousser ou supprimer des étiquettes de conteneurs grâce à des règles de protection basées sur les rôles et utilisant des expressions régulières.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/505455) en tant que [version expérimentale](../../../policy/development_stages_support.md) dans GitLab 17.9 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `container_registry_protected_tags`. Fonctionnalité désactivée par défaut.
- [Activée sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/505455) dans GitLab 17.10.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/524076) dans GitLab 17.11. Le feature flag `container_registry_protected_tags` a été supprimé.

{{< /history >}}

Contrôlez qui peut pousser et supprimer des étiquettes de conteneurs dans votre projet.

Par défaut, les utilisateurs disposant du rôle Développeur, Chargé de maintenance ou Propriétaire peuvent pousser et supprimer des étiquettes d'images dans tous les registres de conteneurs du projet. Grâce aux règles de protection des étiquettes, vous pouvez :

- Restreindre la poussée et la suppression d'étiquettes à des rôles utilisateur spécifiques.
- Créer jusqu'à 5 règles de protection par projet.
- Appliquer ces règles à tous les registres de conteneurs de votre projet.

Une étiquette est protégée lorsqu'au moins une règle de protection correspond à son nom. Si plusieurs règles correspondent, la règle la plus restrictive s'applique.

Les étiquettes protégées ne peuvent pas être supprimées par les [politiques de nettoyage](reduce_container_registry_storage.md#cleanup-policy).

## Prérequis {#prerequisites}

Avant de pouvoir utiliser les étiquettes de conteneurs protégées :

- Vous devez utiliser la nouvelle version du registre de conteneurs :
  - GitLab.com : activé par défaut
  - GitLab Self-Managed : [Activer la base de données de métadonnées](../../../administration/packages/container_registry_metadata_database.md)

## Créer une règle de protection {#create-a-protection-rule}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire

Pour créer une règle de protection :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Développez **Registre de conteneurs**.
1. Sous **Étiquettes de conteneurs protégées**, sélectionnez **Ajouter une règle de protection**.
1. Remplissez les champs :
   - **Protéger les étiquettes de conteneurs correspondant à** : saisissez un modèle d'expression régulière en utilisant la [syntaxe RE2](https://github.com/google/re2/wiki/Syntax). Les modèles ne doivent pas dépasser 100 caractères. Consultez les [exemples de modèles d'expressions régulières](#regex-pattern-examples).
   - **Niveau minimal de rôle autorisé à effectuer des poussées** : sélectionnez Chargé de maintenance, Propriétaire ou Administrateur.
   - **Niveau minimal de rôle autorisé à effectuer des suppressions** : sélectionnez Chargé de maintenance, Propriétaire ou Administrateur.
1. Sélectionnez **Ajouter une règle**.

La règle de protection est créée et les étiquettes correspondantes sont protégées.

## Exemples de modèles d'expressions régulières {#regex-pattern-examples}

Exemples de modèles que vous pouvez utiliser pour protéger des étiquettes de conteneurs :

| Modèle           | Description |
|-------------------|-------------|
| `.*`              | Protège toutes les étiquettes |
| `^v.*`            | Protège les étiquettes commençant par « v » (comme `v1.0.0`, `v2.1.0-rc1`) |
| `\d+\.\d+\.\d+`   | Protège les étiquettes de version sémantique (comme `1.0.0`, `2.1.0`) |
| `^latest$`        | Protège l'étiquette `latest` |
| `.*-stable$`      | Protège les étiquettes se terminant par « -stable » (comme `1.0-stable`, `main-stable`) |
| `stable\|release` | Protège les étiquettes contenant « stable » ou « release » (comme `1.0-stable`) |

## Supprimer une règle de protection {#delete-a-protection-rule}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire

Pour supprimer une règle de protection :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Paquets et registres**.
1. Développez **Registre de conteneurs**.
1. Sous **Étiquettes de conteneurs protégées**, à côté de la règle de protection que vous souhaitez supprimer, sélectionnez **Supprimer** ({{< icon name="remove" >}}).
1. Lorsqu'une confirmation vous est demandée, sélectionnez **Supprimer**.

La règle de protection est supprimée et les étiquettes correspondantes ne sont plus protégées.

## Délai de propagation {#propagation-delay}

Les modifications de règles s'appuient sur des jetons JWT pour se propager entre les services. Par conséquent, les modifications apportées aux règles de protection et aux rôles d'accès des utilisateurs peuvent ne prendre effet qu'après l'expiration des jetons JWT en cours. Le délai est égal à la [durée de jeton configurée](../../../administration/packages/container_registry.md#increase-token-duration) :

- Par défaut : 5 minutes
- GitLab.com : [15 minutes](../../gitlab_com/_index.md#container-registry)

La plupart des clients du registre de conteneurs (notamment Docker, l'interface utilisateur GitLab et l'API) demandent un nouveau jeton pour chaque opération, mais les clients personnalisés peuvent conserver un jeton pendant toute sa période de validité.

## Suppressions de manifestes d'images {#image-manifest-deletions}

L'interface utilisateur GitLab et l'API ne prennent pas en charge la suppression directe de manifestes d'images. Par le biais d'appels directs à l'API du registre de conteneurs, les suppressions de manifestes affectent toutes les étiquettes associées.

Pour garantir la protection des étiquettes, les demandes de suppression directe de manifestes ne sont autorisées que dans les cas suivants :

- La protection des étiquettes est désactivée
- L'utilisateur dispose de l'autorisation de supprimer toutes les étiquettes protégées

## Suppression d'images de conteneurs {#deleting-container-images}

Vous ne pouvez pas [supprimer des images de conteneurs](delete_container_registry_images.md) si toutes les conditions suivantes sont remplies :

- L'image de conteneur possède des étiquettes.
- Le projet dispose de règles de protection des étiquettes du registre de conteneurs.
- Votre niveau d'accès est inférieur à `minimum_access_delete_level` défini dans l'une des règles.

Cette restriction s'applique quelle que soit la correspondance des modèles de règles avec les étiquettes d'images de conteneurs.
