---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Asana
description: "Configurez l'intégration Asana pour ajouter des messages de commit en tant que commentaires aux tâches Asana et fermer des tâches depuis des commits GitLab."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Prise en charge du format d'URL Asana V1 [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/523692) dans GitLab 18.3.

{{< /history >}}

L'intégration Asana ajoute des messages de commit en tant que commentaires aux tâches Asana. Après avoir activé l'intégration, les messages de commit sont vérifiés pour détecter les URL de tâches Asana (par exemple, `https://app.asana.com/1/12345/project/67890/task/987654`) ou les ID de tâches commençant par `#` (par exemple, `#987654`). Le commentaire de commit est ajouté à chaque ID de tâche trouvé.

Vous pouvez également fermer une tâche avec un message contenant : `fix #123456`. Vous pouvez utiliser l'un de ces mots :

- `fix`
- `fixed`
- `fixes`
- `fixing`
- `close`
- `closes`
- `closed`
- `closing`

Consultez également la [documentation de l'API d'intégration Asana](../../../api/project_integrations.md#asana).

## Configuration {#setup}

Dans Asana, créez un jeton d'accès personnel. [En savoir plus sur les jetons d'accès personnels dans Asana](https://developers.asana.com/docs/personal-access-token).

Effectuez ces étapes dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Asana**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Collez le jeton que vous avez généré dans Asana.
1. Facultatif. Pour restreindre ce paramètre à des branches spécifiques, listez-les dans le champ **Restreindre à la branche**, séparées par des virgules.
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.
