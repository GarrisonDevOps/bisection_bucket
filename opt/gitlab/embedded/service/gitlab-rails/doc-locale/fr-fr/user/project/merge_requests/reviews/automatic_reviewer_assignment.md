---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Assignez automatiquement des propriétaires du code comme relecteurs, ou obtenez des recommandations de relecteurs via le Recommend Reviewers Flow."
title: Attribution automatique de relecteurs et recommandations
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab peut attribuer ou recommander des relecteurs pour vos merge requests, afin que vous n'ayez pas à les sélectionner manuellement :

- Utilisez l'attribution automatique de relecteurs pour assigner les propriétaires du code des fichiers modifiés en tant que relecteurs.
- Utilisez le Recommend Reviewers Flow pour obtenir des recommandations de relecteurs basées sur vos règles d'approbation, y compris les règles de propriétaires du code.

## Attribution automatique de relecteurs {#automatic-reviewer-assignment}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224175) dans GitLab 18.10 [avec le feature flag](../../../../administration/feature_flags/_index.md) `auto_assign_code_owner_reviewers`. Fonctionnalité désactivée par défaut.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/239965) dans GitLab 19.1. Le feature flag `auto_assign_code_owner_reviewers` a été supprimé.

{{< /history >}}

Lorsque vous activez l'attribution automatique des relecteurs, GitLab désigne les [Propriétaires du code](../../codeowners/_index.md) des fichiers modifiés comme relecteurs de la merge request.

Prérequis :

- Le projet doit avoir un fichier `CODEOWNERS`.
- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

### Activer l'attribution automatique des relecteurs {#enable-automatic-reviewer-assignment}

Pour activer l'attribution automatique des relecteurs pour un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Accédez à la section **Affectation automatique d'un relecteur ou d'une relectrice**.
1. Sélectionnez **Désigner automatiquement l'ensemble des propriétaires de code en tant que relecteurs ou relectrices**.
1. Sélectionnez **Enregistrer les modifications**.

### Conditions d'attribution des relecteurs par GitLab {#when-gitlab-assigns-reviewers}

Une fois le paramètre activé, GitLab désigne les Propriétaires du code comme relecteurs dans les cas suivants :

- Une merge request est créée directement comme prête.
- Une merge request en brouillon est marquée comme prête.

GitLab désigne comme relecteur chaque Propriétaire du code associé aux fichiers modifiés dans la merge request.

GitLab n'effectue pas l'attribution automatique dans les cas suivants :

- La merge request est en brouillon.
- La merge request comporte déjà un relecteur. [`@GitLabDuo`](../duo_in_merge_requests.md#use-gitlab-duo-to-review-your-code) est exclu de cette vérification.
- Aucun Propriétaire du code n'est associé aux fichiers modifiés dans la merge request.
- La personne à l'origine de la merge request ne dispose pas de l'autorisation nécessaire pour en définir les métadonnées.

## Recommend Reviewers Flow {#recommend-reviewers-flow}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/236211) dans GitLab 19.0 en tant que paramètre de projet en [version bêta](../../../../policy/development_stages_support.md#beta) [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `dap_powered_recommend_reviewers`. Fonctionnalité désactivée par défaut.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/607677) dans GitLab 19.4 pour utiliser un déclencheur de flow au lieu d'un paramètre de projet. Le feature flag `dap_powered_recommend_reviewers` a été supprimé.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257534) dans GitLab 19.5 pour créer un déclencheur qui s'exécute lors de la création d'une merge request.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257235) dans GitLab 19.5 pour recommander des relecteurs dans la barre latérale de la merge request au lieu de les assigner.
- La demande de recommandations pour les merge requests existantes a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/260988) dans GitLab 19.5.
- [Généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261192) dans GitLab 19.5.

{{< /history >}}

Le Recommend Reviewers Flow recommande les relecteurs les mieux adaptés pour réviser votre merge request. Il recommande le nombre minimum de relecteurs nécessaires pour satisfaire chaque règle d'approbation, et choisit les relecteurs en fonction de leur disponibilité, de leur charge de travail et de leur fuseau horaire.

Les relecteurs recommandés apparaissent dans la barre latérale de la merge request et vous choisissez lesquels assigner.

Cette fonctionnalité s'exécute sur la [plateforme GitLab Duo Agent](../../../duo_agent_platform/_index.md).

Ce flow remplace le paramètre de projet **Reviewer assignment strategy** utilisé dans GitLab 19.3 et versions antérieures.

Prérequis :

- Le rôle Propriétaire pour le groupe principal, et le rôle Maintainer ou Propriétaire pour le projet.
- Satisfaire aux [prérequis pour GitLab Duo Agent Platform](../../../duo_agent_platform/_index.md#prerequisites).
- **Autoriser l'exécution du flow**, **Autoriser les flows par défaut** et **Recommander des relecteurs/relectrices** activés [pour le groupe principal](../../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off).

Pour une démonstration interactive, consultez [Recommend Reviewers Flow](https://click-through-demo-generator-v-2-d63870.gitlab.io/demos/recommended-reviewer-flow/).
<!-- Demo published on 2026-10-14 -->

### Utiliser le flow {#use-the-flow}

Lorsque vous activez le Recommend Reviewers Flow pour le groupe principal, GitLab crée un déclencheur de flow dans chaque projet. Ce déclencheur exécute le flow lors de la création d'une merge request, y compris les merge requests créées en tant que brouillons et les merge requests créées à l'état prêt. Pour une merge request en brouillon, le flow recommande des relecteurs lors de la création de la merge request, et non lorsqu'elle est marquée comme prête.

Ce déclencheur apparaît sur la page **IA** > **Déclencheurs** du projet, où vous pouvez le désactiver.

Pour exécuter le flow lorsqu'une merge request en brouillon est marquée comme prête, désactivez ce déclencheur, puis créez un déclencheur :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **IA** > **Déclencheurs**.
1. Sélectionnez **Nouveau déclencheur de flow**.
1. Dans **Description**, saisissez une description pour le déclencheur.
1. Si **Source de configuration** est affiché, sélectionnez **Flux ou agent externe**, puis sélectionnez **Recommander des relecteurs/relectrices** dans la liste des flows.
1. Dans la section **Conditions** :
   1. Sélectionnez **Ajouter une condition**, puis sélectionnez **Sur un événement**.
   1. Dans la liste déroulante **Événement**, sélectionnez **Requête de fusion**.
   1. Dans la liste déroulante **S'exécutent quand**, sélectionnez **Marqué comme prêt**.
   1. Sélectionnez **Ajouter un événement**.
1. Sélectionnez **Créer un déclencheur de flow**.

Le flow s'exécute lorsqu'une personne disposant au minimum du rôle Développeur marque une merge request en brouillon comme prête.

Pour plus d'informations sur la création et la modification des déclencheurs, consultez [les déclencheurs](../../../duo_agent_platform/triggers/_index.md).

### Demander des recommandations pour une merge request existante {#request-recommendations-for-an-existing-merge-request}

Si une merge request existait avant que vous activiez le flow, vous devez démarrer le flow manuellement.

Prérequis :

- Disposer du rôle Développeur, Chargé de maintenance ou Propriétaire pour le projet.

Pour demander des recommandations pour une merge request où le flow ne s'est pas encore exécuté :

- Dans la barre latérale droite, sous **Relecteur** > **Recommandé**, sélectionnez **Générer**.

**Générer** n'est pas disponible pendant l'exécution du flow.

### Assigner un relecteur recommandé {#assign-a-recommended-reviewer}

Une fois le flow exécuté, les relecteurs recommandés apparaissent dans la section **Recommandé** sous **Relecteur** dans la barre latérale droite, regroupés par règle d'approbation. La section apparaît lorsqu'il y a au moins une recommandation.

Pour voir pourquoi le flow a recommandé un utilisateur, et à quel moment, survolez l'utilisateur.

Prérequis :

- Disposer du rôle Développeur, Chargé de maintenance ou Propriétaire pour le projet.

Pour assigner un relecteur recommandé à votre merge request :

- Sous **Recommandé**, à côté de l'utilisateur que vous souhaitez assigner, sélectionnez **Ajouter un relecteur** ({{< icon name="plus" >}}).

Après avoir assigné un relecteur, il n'apparaît plus dans la section **Recommandé**.

Pour exécuter à nouveau le flow et obtenir de nouvelles recommandations :

- Dans la section **Recommandé**, sélectionnez **Actions du relecteur recommandé** ({{< icon name="ellipsis_v" >}}) > **Actualiser**.

GitLab supprime les recommandations lorsque la merge request est fusionnée ou fermée.

### Exceptions {#exceptions}

- La personne qui crée la merge request, ou la marque comme prête, doit disposer au minimum du rôle Développeur pour le projet. Le flow ne recommande pas de relecteurs lorsque la personne dispose d'un rôle inférieur.

### Sélection des relecteurs {#reviewer-selection}

Le Recommend Reviewers Flow lit les règles d'approbation obligatoires et les règles d'approbation facultatives de la merge request. Une règle d'approbation facultative est une règle qui nécessite zéro approbation. Le flow ignore une règle **Tous les membres** facultative, ainsi que les règles facultatives créées par les politiques d'approbation de merge request. Pour chaque règle que les relecteurs actuels ne satisfont pas encore, le flow recommande le nombre minimum de relecteurs nécessaires pour satisfaire la règle. Le flow ne recommande jamais un utilisateur qui est déjà relecteur. Pour chaque relecteur recommandé, le flow enregistre une courte raison pour la recommandation.

Pour choisir parmi les approbateurs éligibles pour une règle, le flow prend en compte les éléments suivants pour chaque approbateur :

- La disponibilité, d'après le [statut](../../../profile/_index.md#set-your-status) de l'approbateur
- La charge de relecture, d'après le nombre de merge requests ouvertes en attente d'une relecture de sa part
- L'heure locale, d'après le fuseau horaire indiqué dans son profil
- L'activité la plus récente

Pour la règle **Tous les membres** par défaut, qui ne liste aucun approbateur, le flow choisit parmi les membres directs du projet qui peuvent à la fois approuver la merge request et fusionner dans la branche cible. Lorsqu'aucun rôle ne peut fusionner dans la branche cible, les candidats sont tous les membres directs pouvant approuver. Les membres qui obtiennent leur accès via un groupe parent ou un groupe invité ne sont pas candidats ; ainsi, un projet sans membres directs ne reçoit aucune recommandation pour cette règle.

La recommandation s'exécute en arrière-plan, les relecteurs recommandés peuvent donc prendre un moment avant d'apparaître. Le flow s'exécute en tant que [compte de service](../../../duo_agent_platform/flows/foundational_flows/_index.md#service-accounts) configuré lors de l'activation du flow pour le groupe principal.

## Sujets connexes {#related-topics}

- [Propriétaires du code](../../codeowners/_index.md)
- [Revues de merge request](_index.md)
- [Règles d'approbation des merge requests](../approvals/rules.md)
