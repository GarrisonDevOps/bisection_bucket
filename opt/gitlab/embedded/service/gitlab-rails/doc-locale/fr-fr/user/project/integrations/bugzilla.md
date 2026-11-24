---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Bugzilla
description: "Configurez l'intégration Bugzilla pour lier un projet GitLab à un outil de suivi des tickets Bugzilla et référencer les tickets Bugzilla dans GitLab."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Bugzilla](https://www.bugzilla.org/) est un système de suivi de bogues généraliste et un outil de test basés sur le Web.

Vous pouvez configurer Bugzilla en tant que [système externe de suivi des tickets](../../../integration/external-issue-tracker.md) dans GitLab.

Pour activer l'intégration Bugzilla dans un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Bugzilla**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Renseignez les champs obligatoires :

   - **URL du projet** : L'URL du projet dans Bugzilla. Par exemple, pour un produit nommé « Fire Tanuki » : `https://bugzilla.example.org/describecomponents.cgi?product=Fire+Tanuki`.
   - **URL du ticket** : L'URL pour afficher un ticket dans le projet Bugzilla. L'URL doit contenir `:id`. GitLab remplace `:id` par le numéro du ticket (par exemple, `https://bugzilla.example.org/show_bug.cgi?id=:id`, qui devient `https://bugzilla.example.org/show_bug.cgi?id=123`).
   - **URL de nouveau ticket** : L'URL pour créer un nouveau ticket dans le projet Bugzilla lié. Par exemple, pour un projet nommé « My Cool App » : `https://bugzilla.example.org/enter_bug.cgi#h=dupes%7CMy+Cool+App`.

1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

Une fois Bugzilla configuré et activé, un lien apparaît sur les pages du projet GitLab. Ce lien vous redirige vers le projet Bugzilla approprié.

Vous pouvez également désactiver le [suivi interne des tickets GitLab](../issues/_index.md) dans ce projet. Pour plus d'informations sur les étapes et les conséquences de la désactivation des tickets GitLab, consultez :

- [Modifier la visibilité du projet](../../public_access.md#change-project-visibility).
- [Configurer les fonctionnalités et les permissions du projet](../settings/_index.md#configure-project-features-and-permissions).

## Référencer les tickets Bugzilla dans GitLab {#reference-bugzilla-issues-in-gitlab}

Vous pouvez référencer des tickets dans Bugzilla en utilisant :

- `#<ID>`, où `<ID>` est un nombre (par exemple, `#143`).
- `<PROJECT>-<ID>` (par exemple, `API_32-143`) où :
  - `<PROJECT>` commence par une lettre majuscule, suivie de lettres majuscules, de chiffres ou de traits de soulignement.
  - `<ID>` est un nombre.

La partie `<PROJECT>` est ignorée dans les liens, qui pointent toujours vers l'adresse spécifiée dans **URL du ticket**.

Utilisez le format long (`<PROJECT>-<ID>`) si vous avez à la fois des systèmes de suivi de tickets internes et externes activés. Si vous utilisez le format court et qu'un ticket avec le même ID existe dans le système de suivi de tickets interne, le ticket interne est lié.

## Dépannage {#troubleshooting}

Pour les livraisons récentes de webhooks d'intégration, consultez les journaux des webhooks d'intégration.
