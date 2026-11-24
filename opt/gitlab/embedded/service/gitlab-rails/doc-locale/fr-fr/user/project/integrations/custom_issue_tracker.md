---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Gestionnaire de tickets de suivi personnalisé
description: "Configurez une intégration de gestionnaire de tickets de suivi personnalisé pour lier un projet GitLab à un gestionnaire de tickets qui ne dispose pas d'intégration native."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez intégrer un [gestionnaire de tickets externe](../../../integration/external-issue-tracker.md) à GitLab. Si votre gestionnaire de tickets préféré n'est pas répertorié dans la [liste des intégrations](../../../integration/external-issue-tracker.md#configure-an-external-issue-tracker), vous pouvez activer un gestionnaire de tickets de suivi personnalisé.

Une fois le gestionnaire de tickets de suivi personnalisé activé, un lien vers ce gestionnaire apparaît dans la barre latérale gauche de votre projet.

![Lien vers le gestionnaire de tickets de suivi personnalisé dans la barre latérale gauche d'un projet.](img/custom_issue_tracker_v18_3.png)

## Activer un gestionnaire de tickets de suivi personnalisé {#enable-a-custom-issue-tracker}

Pour activer un gestionnaire de tickets de suivi personnalisé dans un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Gestionnaire de tickets de suivi personnalisé**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Renseignez les champs obligatoires :
   - **URL du projet** : L'URL permettant d'afficher tous les tickets dans le gestionnaire de tickets de suivi personnalisé.
   - **URL du ticket** : L'URL permettant d'afficher un ticket dans le gestionnaire de tickets de suivi personnalisé. L'URL doit contenir `:id`. GitLab remplace `:id` par le numéro du ticket (par exemple, `https://customissuetracker.com/project-name/:id`, qui devient `https://customissuetracker.com/project-name/123`).
   - **URL de nouveau ticket** : saisissez n'importe quelle URL. Cette URL n'est pas utilisée et un [ticket existe](https://gitlab.com/gitlab-org/gitlab/-/issues/327503) pour la supprimer.
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

## Référencer des tickets dans un gestionnaire de tickets de suivi personnalisé {#reference-issues-in-a-custom-issue-tracker}

Vous pouvez référencer des tickets dans un gestionnaire de tickets de suivi personnalisé à l'aide des formats suivants :

- `#<ID>`, où `<ID>` est un nombre (par exemple, `#143`).
- `<PROJECT>-<ID>` (par exemple, `API_32-143`) où :
  - `<PROJECT>` commence par une lettre majuscule, suivie de lettres majuscules, de chiffres ou de traits de soulignement.
  - `<ID>` est un nombre.

La partie `<PROJECT>` est ignorée dans les liens, qui pointent toujours vers l'adresse spécifiée dans **URL du ticket**.

Utilisez le format long (`<PROJECT>-<ID>`) si vous avez à la fois des gestionnaires de tickets internes et externes activés. Si vous utilisez le format court et qu'un ticket avec le même identifiant existe dans le gestionnaire de tickets interne, c'est le ticket interne qui est lié.
