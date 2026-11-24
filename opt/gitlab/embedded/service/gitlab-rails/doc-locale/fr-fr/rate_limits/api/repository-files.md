---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
gitlab_dedicated: yes
description: "Configurer les limites de débit pour l'API des fichiers du dépôt."
title: "Limites de débit de l'API des fichiers du dépôt"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'[API des fichiers du dépôt](../../api/repository_files.md) vous permet de récupérer, créer, mettre à jour et supprimer des fichiers dans votre dépôt. Pour améliorer la sécurité et la durabilité de votre application web, vous pouvez appliquer des [limites de débit](../_index.md) sur cette API. Toutes les limites de débit que vous créez pour l'API Files remplacent les [limites de débit générales pour les utilisateurs et les adresses IP](../../administration/settings/user_and_ip_rate_limits.md).

## Définir les limites de débit de l'API Files {#define-files-api-rate-limits}

Les limites de débit pour l'API Files sont désactivées par défaut. Lorsqu'elles sont activées, elles remplacent les limites de débit générales pour les utilisateurs et les adresses IP pour les requêtes adressées à l'[API des fichiers du dépôt](../../api/repository_files.md). Vous pouvez conserver les limites de débit générales pour les utilisateurs et les adresses IP déjà en place, et augmenter ou diminuer les limites de débit pour l'API Files. Aucune autre nouvelle fonctionnalité n'est fournie par ce remplacement.

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

Pour remplacer les limites de débit générales pour les utilisateurs et les adresses IP pour les requêtes adressées à l'API des fichiers du dépôt :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limites de débit de l'API Files**.
1. Cochez les cases correspondant aux types de limites de débit que vous souhaitez activer :
   - **Limite de débit des requêtes d'API non authentifiées**
   - **Limite de débit des requêtes d'API authentifiées**
1. Si vous avez sélectionné **non authentifiée** :
   1. Sélectionnez le **Nombre maximal de requêtes d'API non authentifiées par période par IP**.
   1. Sélectionnez la **Durée de la limitation de fréquence des requêtes d'API non authentifiées en secondes**.
1. Si vous avez sélectionné **authentifiée** :
   1. Sélectionnez le **Nombre maximal de requêtes d'API authentifiées par période par utilisateur**.
   1. Sélectionnez la **Limitation de fréquence des requêtes d'API authentifiées en secondes**.

## Configurer les limites de débit pour le blame de fichier {#configure-file-blame-rate-limits}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261912) dans GitLab 19.6.

{{< /history >}}

Le [point de terminaison du blame de fichier](../../api/repository_files.md#retrieve-file-blame-history-from-a-repository) et le champ GraphQL `blame` sur `RepositoryBlob` partagent ces limites de débit. Pour GraphQL, chaque blob dans une requête est comptabilisé comme une seule requête. Ces limites s'appliquent en plus des limites de débit de l'API Files et sont activées par défaut.

| Type de requête    | Limite par défaut             | S'applique à            | Paramètre d'application |
|-----------------|---------------------------|-----------------------|---------------------|
| Authentifiée   | 400 requêtes par minute | Chaque utilisateur et projet | `project_repositories_blame_limit` |
| Non authentifiée | 400 requêtes par minute | Chaque adresse IP       | `project_repositories_blame_unauthenticated_limit` |

Pour modifier une limite, utilisez l'[API des paramètres d'application](../../api/settings.md#available-settings). Définissez une limite à `0` pour la désactiver.

## Sujets connexes {#related-topics}

- [Limites de fréquence](../_index.md)
- [API des fichiers du dépôt](../../api/repository_files.md)
- [Limites de débit pour les utilisateurs et les adresses IP](../../administration/settings/user_and_ip_rate_limits.md)
