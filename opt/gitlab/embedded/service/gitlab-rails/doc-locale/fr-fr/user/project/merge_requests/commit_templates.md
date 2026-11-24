---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Utilisez des modèles de message de commit pour vous assurer que les commits de votre projet GitLab contiennent toutes les informations nécessaires et sont correctement formatés.
title: Templates de message de commit
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab utilise des modèles de commit pour créer des messages par défaut pour des types de commits spécifiques. Ces modèles encouragent les messages de commit à suivre un format particulier ou à contenir des informations spécifiques. Les utilisateurs peuvent remplacer ces modèles lors de la fusion d'une merge request.

La syntaxe des modèles de commit est similaire à la syntaxe des [suggestions de révision](reviews/suggestions.md#configure-the-commit-message-for-applied-suggestions).

GitLab Duo peut également vous aider à générer des [messages de commit de fusion](duo_in_merge_requests.md#generate-a-merge-commit-message), même si vous ne configurez pas de modèles.

## Configurer des modèles de commit {#configure-commit-templates}

Modifiez les modèles de commit de votre projet si les modèles par défaut ne contiennent pas les informations dont vous avez besoin.

Prérequis :

- Vous devez avoir le rôle Maintainer ou Owner pour un projet.

Pour cela :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Selon le type de modèle que vous souhaitez créer, faites défiler vers [**Modèle de message pour les validations de fusion**](#default-template-for-merge-commits) ou [**Modèle de message pour les validations squash**](#default-template-for-squash-commits).
1. Pour le type de commit souhaité, saisissez votre message par défaut. Vous pouvez utiliser à la fois du texte statique et des [variables](#supported-variables-in-commit-templates). Chaque modèle est limité à 500 caractères, bien qu'après le remplacement des modèles par des données, le message final puisse être plus long.
1. Sélectionnez **Enregistrer les modifications**.

## Modèle par défaut pour les commits de fusion {#default-template-for-merge-commits}

Le modèle par défaut pour les messages de commit de fusion est :

```plaintext
Merge branch '%{source_branch}' into '%{target_branch}'

%{title}

%{issues}

See merge request %{reference}
```

## Modèle par défaut pour les commits squash {#default-template-for-squash-commits}

Si vous avez configuré votre projet pour [fusionner les commits en squash](squash_and_merge.md), GitLab crée un message de commit squash avec ce modèle :

```plaintext
%{title}
```

## Variables prises en charge dans les modèles de commit {#supported-variables-in-commit-templates}

{{< history >}}

- Variable `merge_request_author` [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/152510) dans GitLab 17.1.
- Variable `commits_count` [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/383062) dans GitLab 19.5.

{{< /history >}}

Les modèles de message de commit prennent en charge ces variables :

| Variable                                | Description                                                                                                                                                                                                                                   | Exemple de résultat                                                                                                                                                                                   |
|-----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `%{source_branch}`                      | Le nom de la branche à fusionner.                                                                                                                                                                                                              | `my-feature-branch`                                                                                                                                                                              |
| `%{target_branch}`                      | Le nom de la branche sur laquelle appliquer les modifications.                                                                                                                                                                                               | `main`                                                                                                                                                                                           |
| `%{title}`                              | Titre de la merge request.                                                                                                                                                                                                                   | `Fix tests and translations`                                                                                                                                                                     |
| `%{issues}`                             | Chaîne contenant la phrase `Closes <issue numbers>`. Contient tous les tickets mentionnés dans la description de la merge request qui correspondent aux [modèles de fermeture de tickets](../issues/managing_issues.md#closing-issues-automatically). Vide si aucun ticket n'est mentionné. | `Closes #465, #190 and #400`                                                                                                                                                                     |
| `%{description}`                        | Description de la merge request.                                                                                                                                                                                                             | `Merge request description.`<br>`Can be multiline.`                                                                                                                                              |
| `%{reference}`                          | Référence à la merge request.                                                                                                                                                                                                               | `group-name/project-name!72359`                                                                                                                                                                  |
| `%{local_reference}`                    | Référence locale à la merge request.                                                                                                                                                                                                         | `!72359`                                                                                                                                                                                         |
| `%{source_project_id}`                  | ID du projet source de la merge request.                                                                                                                                                                                                     | `123`                                                                                                                                                                                            |
| `%{first_commit}`                       | Message complet du premier commit dans le diff de la merge request.                                                                                                                                                                                       | `Update README.md`                                                                                                                                                                               |
| `%{first_multiline_commit}`             | Message complet du premier commit qui n'est pas un commit de fusion et qui comporte plus d'une ligne dans le corps du message. Titre de la merge request si tous les commits ne sont pas multilignes.                                                                                   | `Update README.md`<br><br>`Improved project description in readme file.`                                                                                                                         |
| `%{first_multiline_commit_description}` | Description (sans la première ligne/le titre) du premier commit qui n'est pas un commit de fusion et qui comporte plus d'une ligne dans le corps du message.                                                                                                          | `Improved project description in readme file.`                                                                                                                                                   |
| `%{url}`                                | URL complète de la merge request.                                                                                                                                                                                                                | `https://gitlab.com/gitlab-org/gitlab/-/merge_requests/1`                                                                                                                                        |
| `%{reviewed_by}`                        | Liste séparée par des sauts de ligne des relecteurs de la merge request, basée sur les utilisateurs qui soumettent une révision à l'aide de commentaires groupés, au format de trailer Git commit `Reviewed-by`.                                                                                 | `Reviewed-by: Sidney Jones <sjones@example.com>` <br> `Reviewed-by: Zhang Wei <zwei@example.com>`                                                                                                |
| `%{approved_by}`                        | Liste séparée par des sauts de ligne des approbateurs de la merge request, au format de trailer Git commit `Approved-by`.                                                                                                                                              | `Approved-by: Sidney Jones <sjones@example.com>` <br> `Approved-by: Zhang Wei <zwei@example.com>`                                                                                                |
| `%{merged_by}`                          | Utilisateur qui a fusionné la merge request.                                                                                                                                                                                                            | `Alex Garcia <agarcia@example.com>`                                                                                                                                                              |
| `%{merge_request_author}`               | Nom et adresse e-mail de l'auteur de la merge request.                                                                                                                                                                                                   | `Zane Doe <zdoe@example.com>`                                                                                                                                                                    |
| `%{co_authored_by}`                     | Noms et adresses e-mail des auteurs de commits au format de trailer Git commit `Co-authored-by`. Limité aux auteurs des 100 commits les plus récents de la merge request.                                                                                           | `Co-authored-by: Zane Doe <zdoe@example.com>` <br> `Co-authored-by: Blake Smith <bsmith@example.com>`                                                                                            |
| `%{all_commits}`                        | Messages de tous les commits de la merge request. Limité aux 100 commits les plus récents. Ignore les corps de commit dépassant 100 Kio et les messages de commit de fusion.                                                                                          | `* Feature introduced` <br><br> `This commit implements feature` <br> `Changelog:added` <br><br> `* Bug fixed` <br><br> `* Documentation improved` <br><br>`This commit introduced better docs.` |
| `%{commits_count}`                      | Nombre de commits dans la merge request.                                                                                                                                                                                                       | `3`                                                                                                                                                                                              |

Toute ligne ne contenant qu'une variable vide est supprimée. Si la ligne supprimée est à la fois précédée et suivie d'une ligne vide, la ligne vide précédente est également supprimée.

Après avoir modifié un message de commit sur une merge request ouverte, GitLab met automatiquement à jour le message de commit. Pour restaurer le message de commit au modèle du projet, rechargez la page.

## Sujets connexes {#related-topics}

- [Templates de titre de merge request](title_templates.md)
- [Squash et merge](squash_and_merge.md)
