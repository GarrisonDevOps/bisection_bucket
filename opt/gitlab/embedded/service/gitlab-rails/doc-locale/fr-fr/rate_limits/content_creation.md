---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Configurer les limites de débit pour la création de tickets, d'epics et de notes."
title: Limites de débit pour la création de contenu
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Les limites de débit contrôlent la cadence à laquelle les utilisateurs peuvent créer des tickets, des epics et des notes.

## Création de tickets et d'epics {#issue-and-epic-creation}

La limite de création d'[epic](../user/group/epics/_index.md) est la même que celle appliquée à la création de tickets.

Prérequis :

- Disposer d'un accès administrateur.

Pour limiter le nombre de requêtes effectuées vers les endpoints de création de tickets et d'epics :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limites de fréquence des tickets**.
1. Sous **Nombre maximal de requêtes par minute**, saisissez la nouvelle valeur.
1. Sélectionnez **Enregistrer les modifications**.

La limite de débit :

- Est appliquée indépendamment par projet et par utilisateur.
- N'est pas appliquée par adresse IP.
- Est désactivée par défaut.
- Peut être définie sur `0` pour désactiver la limite de débit.

Les requêtes dépassant la limite de débit sont consignées dans le fichier `auth.log`.

Par exemple, si vous définissez la limite à `300`, les requêtes dépassant un débit de 300 par minute sont bloquées. L'accès à l'endpoint est disponible après une minute.

## Création de notes {#note-creation}

Vous pouvez configurer la limite de débit pour les requêtes vers l'endpoint de création de notes.

Prérequis :

- Disposer d'un accès administrateur.

Pour modifier la limite de débit de création de notes :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limite de fréquence des requêtes liées aux notes**.
1. Dans le champ **Nombre maximum de requêtes par minute**, saisissez la nouvelle valeur.
1. Facultatif. Dans le champ **Utilisateurs à exclure de la limitation de fréquence**, listez les utilisateurs autorisés à dépasser la limite.
1. Sélectionnez **Enregistrer les modifications**.

La limite de débit :

- Est appliquée indépendamment par utilisateur.
- N'est pas appliquée par adresse IP.
- Par défaut : `300`.

Les requêtes dépassant la limite de débit sont consignées dans le fichier `auth.log`.

Par exemple, si vous définissez la limite à `300`, les requêtes dépassant un débit de 300 par minute sont bloquées. L'accès à l'endpoint est disponible après une minute.

## Sujets connexes {#related-topics}

- [Limites de fréquence](_index.md)
- [Limites de débit non configurables](non_configurable.md)
