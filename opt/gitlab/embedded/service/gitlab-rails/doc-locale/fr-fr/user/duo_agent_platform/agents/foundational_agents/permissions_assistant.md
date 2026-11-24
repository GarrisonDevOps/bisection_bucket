---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Assistant Autorisations
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduite](https://gitlab.com/gitlab-org/gitlab/-/work_items/592230) en tant que fonctionnalité en [version bêta](../../../../policy/development_stages_support.md#beta) dans GitLab 18.11.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/596613) dans GitLab 19.2.

{{< /history >}}

L'Assistant Autorisations est un agent GitLab Duo qui vous aide à choisir les [autorisations précises](../../../../auth/tokens/fine_grained_access_tokens.md) appropriées lors de la création d'un jeton d'accès personnel.

Décrivez ce que vous souhaitez que le jeton fasse, et l'Assistant Autorisations sélectionne les autorisations appropriées dans le formulaire de création. Vous pouvez poser des questions de suivi ou affiner votre demande jusqu'à ce que la sélection corresponde à vos besoins.

## Prérequis {#prerequisites}

- Satisfaire aux [prérequis pour GitLab Duo Agent Platform](../../_index.md#prerequisites).
- Avoir les [agents par défaut activés](_index.md#turn-foundational-agents-on-or-off).
- Avoir les jetons d'accès personnels à granularité fine activés. Cette fonctionnalité est contrôlée par le feature flag `granular_personal_access_tokens`, qui est activé par défaut.

## Utiliser l'Assistant Autorisations {#use-the-permissions-assistant}

L'Assistant Autorisations est disponible sur la page de création de jetons d'accès personnels à granularité fine dans l'interface utilisateur de GitLab.

Pour utiliser l'Assistant Autorisations :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Jetons d'accès personnel**.
1. Dans la liste déroulante **Générer un jeton**, sélectionnez **Jeton affiné**.
1. Sélectionnez **Ajouter des autorisations avec Duo**.

   Un panneau Duo Chat s'ouvre avec l'Assistant Autorisations présélectionné.
1. Décrivez ce que vous souhaitez que le jeton fasse, ou sélectionnez l'une des invites suggérées.

   L'Assistant Autorisations sélectionne les autorisations appropriées dans le formulaire.
1. Vérifiez les autorisations sélectionnées et affinez votre demande si nécessaire.
1. Renseignez les champs restants du jeton et sélectionnez **Générer un jeton**.

### Conseils pour de meilleurs résultats {#tips-for-best-results}

- Décrivez votre cas d'utilisation de manière précise. Par exemple, « J'ai besoin de lire des tickets et de créer des merge requests dans un seul projet » donne de meilleurs résultats que « J'ai besoin d'un accès à l'API ».
- Si la sélection initiale est trop large ou trop restreinte, demandez des ajustements.
- Utilisez les invites suggérées comme point de départ si vous ne savez pas comment décrire vos besoins.
- Les suggestions sont appliquées au niveau d'accès pertinent (Groupe et projet, Utilisateur ou Global) ; ainsi, la même autorisation peut être ajoutée dans plusieurs sections lorsque votre demande les concerne.

## Exemples de prompts {#example-prompts}

- « Je veux lire et écrire dans des dépôts via l'API. »
- « J'ai besoin de gérer les pipelines CI/CD et de lire les job logs. »
- « Je veux automatiser la gestion des tickets et des merge requests. »
- « J'ai besoin d'un accès en lecture seule aux projets et aux groupes. »
- « Je veux lire tous les extraits de code, pas seulement les miens. »
