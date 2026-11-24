---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Définir des limites de débit pour les API dépréciées sur GitLab.
gitlab_dedicated: yes
title: Limites de débit des API dépréciées
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les endpoints d'API dépréciés ont été remplacés par des fonctionnalités alternatives, mais ils ne peuvent pas être supprimés sans rompre la compatibilité ascendante. Pour encourager les utilisateurs à passer à l'alternative, définissez une limite de débit restrictive sur les endpoints dépréciés.

## Endpoints d'API dépréciés {#deprecated-api-endpoints}

Cette limite de débit ne comprend pas tous les endpoints d'API dépréciés, uniquement ceux susceptibles d'affecter les performances :

- [`GET /groups/:id`](../../api/groups.md#retrieve-a-group) sans le paramètre de requête `with_projects=0`.

## Définir des limites de débit pour les API dépréciées {#define-deprecated-api-rate-limits}

Les limites de débit pour les endpoints d'API dépréciés sont désactivées par défaut. Lorsqu'elles sont activées, elles remplacent les limites de débit générales par utilisateur et par IP pour les requêtes vers les endpoints dépréciés. Vous pouvez conserver les limites de débit générales par utilisateur et par IP déjà en place, et augmenter ou diminuer les limites de débit pour les endpoints d'API dépréciés. Aucune autre nouvelle fonctionnalité n'est fournie par ce remplacement.

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

Pour remplacer les limites de débit générales par utilisateur et par IP pour les requêtes vers les endpoints d'API dépréciés :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limites de débit des API dépréciées**.
1. Cochez les cases correspondant aux types de limites de débit que vous souhaitez activer :
   - **Limite de débit des requêtes d'API non authentifiées**
   - **Limite de débit des requêtes d'API authentifiées**
1. Si vous avez sélectionné **non authentifié** :
   1. Sélectionnez le **Nombre maximal de requêtes d'API non authentifiées par période par IP**.
   1. Sélectionnez la **Durée de la limitation de fréquence des requêtes d'API non authentifiées en secondes**.
1. Si vous avez sélectionné **authentifié** :
   1. Sélectionnez le **Nombre maximal de requêtes d'API authentifiées par période par utilisateur**.
   1. Sélectionnez la **Limitation de fréquence des requêtes d'API authentifiées en secondes**.

## Sujets connexes {#related-topics}

- [Limites de fréquence](../_index.md)
- [Limites de débit par utilisateur et par IP](../../administration/settings/user_and_ip_rate_limits.md)
