---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Pivotal Tracker
description: "Configurez l'intégration Pivotal Tracker pour ajouter des messages de commit en tant que commentaires aux stories Pivotal Tracker et clôturer des stories depuis des commits."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'intégration Pivotal Tracker ajoute des messages de commit en tant que commentaires aux stories Pivotal Tracker.

Une fois l'intégration activée, les messages de commit sont vérifiés pour détecter des crochets contenant un signe dièse suivi de l'identifiant de la story (par exemple, `[#555]`). Le commentaire de commit est ajouté à chaque identifiant de story trouvé.

Vous pouvez également clôturer une story avec un message contenant : `fix [#555]`. Vous pouvez utiliser l'un des mots suivants :

- `fix`
- `fixed`
- `fixes`
- `complete`
- `completes`
- `completed`
- `finish`
- `finished`
- `finishes`
- `delivers`

Pour plus d'informations sur l'endpoint des commits sources, consultez l'[API Pivotal Tracker](https://www.pivotaltracker.com/help/api/rest/v5#Source_Commits).

Pour plus d'informations sur l'intégration Pivotal Tracker, consultez l'[API des intégrations de projet](../../../api/project_integrations.md#pivotal-tracker).

## Configurer Pivotal Tracker {#set-up-pivotal-tracker}

Dans Pivotal Tracker, [créez un jeton d'API](https://www.pivotaltracker.com/help/articles/api_token/).

Effectuez ces étapes dans GitLab :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Pivotal Tracker**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Collez le jeton que vous avez généré dans Pivotal Tracker.
1. Facultatif. Pour restreindre ce paramètre à des branches spécifiques, listez-les dans le champ **Restrict to branch**, séparées par des virgules.
1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.
