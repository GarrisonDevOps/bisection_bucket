---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: ClickUp
description: "Configurez l'intégration ClickUp pour lier un projet GitLab à ClickUp et référencer des tickets ClickUp dans des merge requests et des commits."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez utiliser [ClickUp](https://clickup.com/) comme [système de suivi des tickets externe](../../../integration/external-issue-tracker.md). Pour activer l'intégration ClickUp dans un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **ClickUp**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Renseignez les champs obligatoires :

   - **URL du projet** : L'URL du projet ClickUp à lier à ce projet GitLab.
   - **URL du ticket** : L'URL du ticket du projet ClickUp à lier à ce projet GitLab. L'URL doit contenir `:id`. GitLab remplace cet ID par le numéro du ticket.

1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

Une fois ClickUp configuré et activé, un lien apparaît sur les pages du projet GitLab. Le lien vous dirige vers votre projet ClickUp.

Par exemple, voici une configuration pour un projet nommé `gitlab-ci` :

- URL du projet : `https://app.clickup.com/1234567`
- URL du ticket : `https://app.clickup.com/t/1234567/:id`

Vous pouvez également désactiver le [système de suivi des tickets interne de GitLab](../issues/_index.md) dans ce projet. Pour en savoir plus sur les étapes et les conséquences de la désactivation des tickets GitLab, consultez :

- [Modifier la visibilité du projet](../../public_access.md#change-project-visibility).
- [Configurer les fonctionnalités et les permissions du projet](../settings/_index.md#configure-project-features-and-permissions).

## Référencer des tickets ClickUp dans GitLab {#reference-clickup-issues-in-gitlab}

Vous pouvez référencer vos tickets ClickUp en utilisant :

- `#<ID>`, où `<ID>` est une chaîne alphanumrique (exemple : `#8wrtcd932`).
- `CU-<ID>`, où `<ID>` est une chaîne alphanumrique (exemple : `CU-8wrtcd932`).
- `<PROJECT>-<ID>`, par exemple `API_32-143`, où :
  - `<PROJECT>` est un ID de préfixe personnalisé de liste ClickUp.
  - `<ID>` est un nombre.
- Si vous utilisez les [Custom Task IDs](https://help.clickup.com/hc/en-us/sections/17044579323671-Custom-Task-IDs), l'ID de tâche personnalisé complet fonctionne également. Par exemple : `SOP-1234`.

Dans les liens, la partie `CU-` est ignorée et le lien pointe vers l'URL globale du ticket. Lorsqu'un préfixe personnalisé est utilisé dans une liste ClickUp, la partie préfixe fait partie du lien.

Utilisez le format `CU-` (`CU-<ID>`) si vous avez activé à la fois les systèmes de suivi des tickets internes et externes. Si vous utilisez le format court et qu'un ticket avec le même ID existe dans le système de suivi des tickets interne, le ticket interne est lié.

Pour les [Custom Task IDs](https://help.clickup.com/hc/en-us/sections/17044579323671-Custom-Task-IDs), vous devez inclure l'ID complet, y compris votre préfixe personnalisé. Par exemple, `SOP-1432`.
