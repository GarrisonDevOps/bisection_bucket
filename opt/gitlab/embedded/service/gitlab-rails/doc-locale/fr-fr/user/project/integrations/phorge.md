---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Phorge
description: "Configurez l'intégration Phorge pour lier un projet GitLab à une instance Phorge et référencer des tâches Phorge dans GitLab."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez utiliser [Phorge](https://we.phorge.it/) comme [système de suivi des tickets externe](../../../integration/external-issue-tracker.md) dans GitLab.

## Configurer l'intégration {#configure-the-integration}

Pour configurer Phorge dans un projet GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Phorge**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Dans **URL du projet**, saisissez l'URL du projet Phorge.
1. Dans **URL du ticket**, saisissez l'URL du ticket du projet Phorge. L'URL doit contenir `:id`. GitLab remplace ce jeton par l'ID de la tâche Maniphest (par exemple, `T123`).
1. Dans **URL de nouveau ticket**, saisissez l'URL d'un nouveau ticket du projet Phorge. Pour préremplir les tags liés à ce projet, vous pouvez utiliser `?tags=`.
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

Dans ce projet GitLab, vous pouvez voir un lien vers votre projet Phorge. Vous pouvez désormais référencer vos tickets et tâches Phorge dans GitLab avec `T<ID>`, où `<ID>` est un ID de tâche Maniphest (par exemple, `T123`).
