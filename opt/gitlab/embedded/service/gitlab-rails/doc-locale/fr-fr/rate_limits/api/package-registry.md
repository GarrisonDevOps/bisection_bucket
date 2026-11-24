---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
gitlab_dedicated: yes
title: "Limitation de la fréquence d'accès au registre de paquets"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Avec le [registre de paquets GitLab](../../user/packages/package_registry/_index.md), vous pouvez utiliser GitLab comme registre privé ou public pour une variété de gestionnaires de paquets courants. Vous pouvez publier et partager des paquets, que d'autres peuvent consommer comme dépendance dans des projets en aval via l'[API Packages](../../api/packages.md).

Si les projets en aval téléchargent fréquemment ces dépendances, de nombreuses requêtes sont effectuées via l'API Packages. Vous pouvez donc atteindre les [limites de débit par utilisateur et par IP](../../administration/settings/user_and_ip_rate_limits.md) appliquées. Pour résoudre ce problème, vous pouvez définir des limites de débit spécifiques pour l'API Packages :

- [Requêtes non authentifiées (par IP)](#enable-unauthenticated-request-rate-limit-for-packages-api).
- [Requêtes d'API authentifiées (par utilisateur)](#enable-authenticated-api-request-rate-limit-for-packages-api).

Ces limites sont désactivées par défaut.

Lorsqu'elles sont activées, elles remplacent les limites de débit générales par utilisateur et par IP pour les requêtes adressées à l'API Packages. Vous pouvez donc conserver les limites de débit générales par utilisateur et par IP, et augmenter les limites de débit pour l'API Packages. En dehors de cette priorité, il n'y a aucune différence de fonctionnalité par rapport aux limites de débit générales par utilisateur et par IP.

## Activer la limite de débit des requêtes non authentifiées pour l'API Packages {#enable-unauthenticated-request-rate-limit-for-packages-api}

Prérequis :

- Disposer d'un accès administrateur.

Pour activer la limite de débit des requêtes non authentifiées :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limitation de la fréquence d'accès au registre de paquets**.
1. Sélectionnez **Activer la limite de fréquence des requêtes non authentifiées**.

   - Facultatif. Mettez à jour la valeur **Nombre maximum de requêtes non authentifiées par période de limite de débit et par IP**. Par défaut : `800`.
   - Facultatif. Mettez à jour la valeur **Période de limite de débit des requêtes non authentifiées en secondes**. Par défaut : `15`.

## Activer la limite de débit des requêtes d'API authentifiées pour l'API Packages {#enable-authenticated-api-request-rate-limit-for-packages-api}

Prérequis :

- Disposer d'un accès administrateur.

Pour activer la limite de débit des requêtes d'API authentifiées :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**
1. Développez **Limitation de la fréquence d'accès au registre de paquets**.
1. Sélectionnez **Activer la limite de fréquence des requêtes d'API authentifiées**.

   - Facultatif. Mettez à jour la valeur **Nombre maximum de requêtes d'API authentifiées par période de limite de fréquence et par utilisateur**. Par défaut : `1000`.
   - Facultatif. Mettez à jour la valeur **Limitation de fréquence des requêtes d'API authentifiées en secondes**. Par défaut : `15`.
