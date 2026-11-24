---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Utilisez la validation du titre des merge requests pour appliquer des conventions de nommage et bloquer les fusions lorsque les titres ne correspondent pas à un modèle regex configuré.
title: Validation du titre des merge requests
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/25689) dans GitLab 17.11 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `merge_request_title_regex`. Fonctionnalité désactivée par défaut.
- [Activée sur GitLab.com et GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/issues/508022) dans GitLab 18.10.
- [Disponible de manière générale](https://gitlab.com/gitlab-org/gitlab/-/issues/508022) dans GitLab 18.10. Le feature flag `merge_request_title_regex` a été supprimé.
- [Modifiée](https://gitlab.com/gitlab-org/gitlab/-/issues/624452) pour ignorer les préfixes de brouillon dans GitLab 19.5.

{{< /history >}}

Vous pouvez appliquer une convention de nommage aux titres des merge requests en les comparant à un modèle d'expression régulière [RE2](https://github.com/google/re2/wiki/Syntax). Lorsque vous configurez un modèle de titre pour un projet, les merge requests dont les titres ne correspondent pas au modèle sont bloquées lors de la fusion.

Utilisez la validation du titre pour :

- Exiger des références de tickets Jira ou de suivi de tickets dans les titres.
- Appliquer la mise en forme des [commits conventionnels](https://www.conventionalcommits.org/).
- Standardiser les préfixes de titre pour les workflows de gestion des releases ou de gouvernance.

## Configurer la validation du titre des merge requests {#configure-merge-request-title-validation}

Configurez un modèle regex que tous les titres de merge requests du projet doivent respecter avant de pouvoir être fusionnées.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour configurer la validation du titre :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres > Requêtes de fusion**.
1. Dans la zone de texte **Modèle de titre**, saisissez un modèle regex.
1. Dans la zone de texte **Exemple de titre**, saisissez une description du format attendu. Incluez un exemple valide afin que les auteurs de merge requests sachent quoi utiliser.
1. Sélectionnez **Enregistrer les modifications**.

![Champs de paramètres de validation du titre pour un projet.](img/title_validation_settings_v18_10.png)

Lorsque vous définissez un **Modèle de titre**, l'**Exemple de titre** est également requis. L'**Exemple de titre** est visible par les utilisateurs lorsque le titre de leur merge request ne correspond pas au modèle.

Pour supprimer la validation du titre, effacez les zones de texte **Modèle de titre** et **Exemple de titre**, puis sélectionnez **Enregistrer les modifications**.

Pour configurer la validation du titre avec l'API, vous pouvez également [utiliser l'API projects](../../../api/projects.md).

## Syntaxe regex {#regex-syntax}

La validation du titre utilise la [syntaxe RE2](https://github.com/google/re2/wiki/Syntax), et non PCRE. RE2 ne prend pas en charge les rétro-références ni les assertions de prévisualisation avant/arrière.

Les champs de modèle et de description ont chacun une longueur maximale de 255 caractères.

Le modèle regex n'a pas besoin de tenir compte des préfixes de brouillon (`[Draft]`, `Draft:` et `(Draft)`) dans les titres des merge requests. La validation du titre les supprime automatiquement avant la comparaison avec le modèle.

### Exemples de modèles {#example-patterns}

Voici des exemples de modèles regex :

- Référence de ticket Jira (exemple de titre valide : `PROJ-123 Fix login bug`) :

  ```plaintext
  ^[A-Z]+-\d+ .+
  ```

- Commits conventionnels (exemple de titre valide : `feat(auth): add SSO support`) :

  ```plaintext
  ^(feat|fix|docs|chore|refactor|test|style)(\(.+\))?: .+
  ```

- Préfixe personnalisé (exemple de titre valide : `BUGFIX: resolve timeout error`) :

  ```plaintext
  ^(FEATURE|BUGFIX|HOTFIX): .+
  ```

- Catégorie entre crochets (exemple de titre valide : `[Feature] Add dark mode`) :

  ```plaintext
  ^\[.+\] .+
  ```

## Application de la validation {#validation-enforcement}

Lorsqu'un modèle de validation du titre est configuré :

- Les merge requests dont les titres ne correspondent pas au modèle ne peuvent pas être fusionnées.
- La vérification du titre apparaît comme une vérification de fusion aux côtés des autres vérifications telles que les approbations, le statut du pipeline et la résolution des fils de discussion.
- Si la [fusion automatique](auto_merge.md) est activée, la merge request attend que le titre corresponde au modèle avant la fusion.
- La validation s'applique au titre actuel au moment de la fusion. Les auteurs peuvent mettre à jour le titre à tout moment avant la fusion.

![Merge request bloquée par la vérification de validation du titre.](img/title_validation_failed_v18_10.png)

## Dépannage {#troubleshooting}

### La merge request ne peut pas être fusionnée en raison de la validation du titre {#merge-request-cannot-be-merged-due-to-title-validation}

Si une merge request est bloquée par la validation du titre :

1. Vérifiez la section des vérifications de fusion de la merge request pour identifier l'échec de la validation du titre.
1. Mettez à jour le titre de la merge request pour qu'il corresponde au modèle configuré dans **Paramètres** > **Requêtes de fusion** > **Modèle de titre**.
1. Utilisez l'**Exemple de titre** affiché dans le message d'erreur comme référence pour le format attendu.

### Le modèle regex ne correspond pas comme prévu {#regex-pattern-does-not-match-as-expected}

La validation du titre utilise la [syntaxe RE2](https://github.com/google/re2/wiki/Syntax), qui diffère de la syntaxe PCRE utilisée par de nombreux outils de test de regex en ligne. Pour vérifier votre modèle :

- Utilisez un outil de test de regex compatible RE2.
- Vérifiez que vous n'utilisez pas de fonctionnalités non prises en charge telles que les rétro-références ou les assertions de prévisualisation avant.
- Vérifiez que les caractères spéciaux sont correctement échappés.

## Sujets connexes {#related-topics}

- [Fusion automatique](auto_merge.md)
- [API Projects - `merge_request_title_regex`](../../../api/projects.md)
- [API de statut de fusion](../../../api/merge_requests.md#merge-status)
