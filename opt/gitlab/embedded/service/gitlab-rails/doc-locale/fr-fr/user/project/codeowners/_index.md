---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Utilisez Code Owners pour définir les experts de votre base de code et définir les exigences de revue en fonction du type ou de l'emplacement du fichier."
title: Propriétaires du code
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Utilisez la fonctionnalité Code Owners pour définir qui a des compétences pour des parties spécifiques de la base de code de votre projet.

Définissez les propriétaires des fichiers et des répertoires dans un dépôt pour :

- Exiger que les propriétaires approuvent les modifications. Combinez les branches protégées avec Code Owners pour exiger que les experts approuvent les merge requests avant qu'elles ne fusionnent dans une branche protégée. Pour plus d'informations, consultez [Code Owners et branches protégées](#code-owners-and-protected-branches).
- Identifier les propriétaires. Les noms des propriétaires du code sont affichés sur les fichiers et les répertoires qu'ils possèdent :

  ![Vue de fichier montrant les propriétaires du code répertoriés sous la description de la modification la plus récente.](img/codeowners_in_UI_v15_10.png)

## Code Owners et règles d'approbation {#code-owners-and-approval-rules}

Combinez Code Owners avec les [règles d'approbation](../merge_requests/approvals/rules.md) des merge requests (facultatives ou obligatoires) pour créer un workflow d'approbation flexible :

- Utilisez Code Owners pour garantir la qualité. Définissez les utilisateurs qui ont une expertise dans des chemins spécifiques de votre dépôt.
- Utilisez les règles d'approbation pour définir des domaines d'expertise qui ne correspondent pas à des chemins de fichiers spécifiques dans votre dépôt. Les règles d'approbation aident à orienter les créateurs de merge requests vers le bon ensemble de relecteurs, tels que les développeurs frontend ou une équipe de sécurité.

Par exemple :

| Type | Nom | Portée  | Commentaire    |
|------|------|--------|------------|
| Règle d'approbation            | UX                   | Tous les fichiers     | Un membre de l'équipe expérience utilisateur (UX) examine l'expérience utilisateur de toutes les modifications apportées dans votre projet. |
| Règle d'approbation            | Sécurité             | Tous les fichiers     | Un membre de l'équipe de sécurité examine toutes les modifications à la recherche de vulnérabilités. |
| Règle d'approbation Code Owner | Frontend : style de code | Fichiers `*.css` | Un ingénieur frontend examine les modifications des fichiers CSS pour s'assurer du respect des normes de style du projet. |
| Règle d'approbation Code Owner | Backend : revue de code | Fichiers `*.rb`  | Un ingénieur backend examine la logique et le style de code des fichiers Ruby. |

<div class="video-fallback">
  Présentation vidéo : <a href="https://www.youtube.com/watch?v=RoyBySTUSB0">Code Owners</a>.
</div>
<figure class="video-container">
  <iframe src="https://www.youtube-nocookie.com/embed/RoyBySTUSB0" frameborder="0" allowfullscreen> </iframe>
</figure>

Pour savoir qui est éligible à l'approbation des merge requests en tant qu'approbateur ou propriétaire du code, consultez [approbateur par type d'appartenance](../merge_requests/approvals/rules.md#approver-by-membership-type).

## Code Owners et branches protégées {#code-owners-and-protected-branches}

Pour vous assurer que les modifications des merge requests sont examinées et approuvées par les propriétaires du code, spécifiés dans le [fichier `CODEOWNERS`](#codeowners-file), la branche cible de la merge request doit être [protégée](../repository/branches/protected.md) et l'[approbation des propriétaires du code](../repository/branches/protected.md#require-code-owner-approval) doit être activée.

Les fonctionnalités suivantes sont disponibles lorsque vous activez les approbations de propriétaires du code sur les branches protégées :

- [Exiger des approbations des propriétaires du code](../repository/branches/protected.md#require-code-owner-approval).
- [Exiger plusieurs approbations des propriétaires du code](advanced.md#require-multiple-approvals-from-code-owners).
- [Approbations facultatives des propriétaires du code](reference.md#optional-sections).

### Exemple pratique {#practical-example}

Votre projet contient des informations sensibles et importantes dans un répertoire `config/`. Vous pouvez :

1. Attribuez la propriété du répertoire. Pour ce faire, configurez un fichier `CODEOWNERS`.
1. Créez une branche protégée pour votre branche par défaut. Par exemple, `main`.
1. Activez **Required approval from code owners** sur la branche protégée.
1. Facultatif. Modifiez le fichier `CODEOWNERS` pour ajouter une règle pour plusieurs approbations.

Avec cette configuration, les merge requests qui modifient des fichiers dans le répertoire `config/` et ciblent la branche `main` nécessitent l'approbation des propriétaires du code désignés avant la fusion.

### Fichiers sans propriétaire du code {#files-without-a-code-owner}

GitLab compare les fichiers modifiés dans une merge request avec le fichier `CODEOWNERS` dans la branche cible. Un fichier qui ne correspond à aucune règle `CODEOWNERS` n'a pas besoin de l'approbation d'un propriétaire du code. Cela inclut les nouveaux fichiers, ainsi que les fichiers qui ont été déplacés ou renommés dans la branche cible pendant qu'une merge request était ouverte.

Pour exiger une approbation pour chaque fichier, ajoutez un propriétaire par défaut avec une entrée `*` en haut du fichier.

Si vous ajoutez des entrées plus spécifiques par la suite, elles remplacent l'entrée `*` car la dernière entrée correspondante est utilisée.

Pour plus d'informations, consultez la [syntaxe `CODEOWNERS`](reference.md) et la [configuration avancée de `CODEOWNERS`](advanced.md).

### Autorisés à pousser et fusionner vers une branche protégée {#allowed-to-push-and-merge-to-a-protected-branch}

Les utilisateurs qui sont **Autorisés à pousser et fusionner** peuvent choisir de créer une merge request pour leurs modifications ou de pousser les modifications directement vers une branche. Si l'utilisateur ignore le processus de merge request, les fonctionnalités de branche protégée et les approbations des propriétaires du code intégrées aux merge requests sont également ignorées.

Cette autorisation est souvent accordée aux comptes associés à l'automatisation ([utilisateurs internes](../../../administration/internal_users.md)) et aux outils de release.

Toutes les modifications des utilisateurs ne disposant pas de l'autorisation **Autorisés à pousser** doivent être acheminées via une merge request.

## Afficher les propriétaires du code d'un fichier ou d'un répertoire {#view-code-owners-of-a-file-or-directory}

Pour afficher les propriétaires du code d'un fichier ou d'un répertoire :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Dépôt**.
1. Accédez au fichier ou au répertoire dont vous souhaitez voir les propriétaires du code.
1. Facultatif. Sélectionnez une branche ou un tag.

GitLab affiche les propriétaires du code en haut de la page.

## Configurer Code Owners {#set-up-code-owners}

Prérequis :

- Vous devez disposer des autorisations pour pousser vers la branche par défaut ou pour créer une merge request.

1. Créez un fichier `CODEOWNERS` dans votre [emplacement préféré](#codeowners-file).
1. Définissez quelques règles dans le fichier en suivant la [syntaxe `CODEOWNERS`](reference.md). Quelques suggestions :
   - Configurez la règle d'approbation [**Tous les utilisateurs/utilisatrices éligibles**](../merge_requests/approvals/rules.md#code-owners-as-approvers).
   - [Exigez l'approbation du propriétaire du code](../repository/branches/protected.md#require-code-owner-approval) sur une branche protégée.
1. Commitez vos modifications et poussez-les vers GitLab.

## Fichier `CODEOWNERS` {#codeowners-file}

Le fichier `CODEOWNERS` définit qui est responsable du code dans un projet GitLab. Son objectif est de :

- Définir les propriétaires du code pour des fichiers et des répertoires spécifiques.
- Appliquer les exigences d'approbation pour les branches protégées.
- Communiquer la propriété du code dans un projet.

Ce fichier détermine qui doit examiner et approuver les modifications et garantit que les bons experts sont impliqués dans les modifications du code.

Chaque dépôt utilise un seul fichier `CODEOWNERS`. GitLab vérifie ces emplacements dans votre dépôt dans cet ordre. Le premier fichier `CODEOWNERS` trouvé est utilisé, et tous les autres sont ignorés :

1. Dans le répertoire racine : `./CODEOWNERS`.
1. Dans le répertoire `docs` : `./docs/CODEOWNERS`.
1. Dans le répertoire `.gitlab` : `./.gitlab/CODEOWNERS`.

Pour plus d'informations, consultez la [syntaxe `CODEOWNERS`](reference.md) et la [configuration avancée de `CODEOWNERS`](advanced.md).

## Sujets connexes {#related-topics}

- [Syntaxe `CODEOWNERS`](reference.md)
- [Configuration avancée de `CODEOWNERS`](advanced.md)
- [Dépannage de Code Owners](troubleshooting.md)
- [Protéger votre dépôt](../repository/protect.md)
- [Branches protégées](../repository/branches/protected.md)
