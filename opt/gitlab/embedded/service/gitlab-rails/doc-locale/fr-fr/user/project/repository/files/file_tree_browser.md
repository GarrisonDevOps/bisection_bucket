---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Utilisez le navigateur d'arborescence de fichiers pour parcourir les fichiers et répertoires d'un dépôt."
title: "Navigateur d'arborescence de fichiers"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/19530) dans GitLab 18.0 [avec le feature flag](../../../../administration/feature_flags/_index.md) `repository_file_tree_browser`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/19530) dans GitLab 18.9.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/537970) dans GitLab 19.2. Le feature flag `repository_file_tree_browser` a été supprimé.

{{< /history >}}

Le navigateur d'arborescence de fichiers est un panneau latéral qui affiche les fichiers et répertoires de votre dépôt dans une structure arborescente réductible. Utilisez-le pour naviguer dans votre dépôt sans faire défiler de longues listes de fichiers.

Le navigateur d'arborescence de fichiers vous permet de :

- Naviguer dans des structures de répertoires imbriqués.
- Afficher la hiérarchie du dépôt.
- Passer d'un fichier à l'autre tout en conservant le contexte de la structure de répertoires.

## Afficher ou masquer le navigateur d'arborescence de fichiers {#show-or-hide-the-file-tree-browser}

Pour afficher ou masquer le navigateur d'arborescence de fichiers :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez aux fichiers de votre dépôt à l'adresse `/<project>/-/tree/<branch>`.
1. Dans le coin supérieur gauche, sélectionnez l'icône du navigateur d'arborescence de fichiers ({{< icon name="file-tree" >}}).

## Naviguer dans les fichiers et répertoires {#navigate-files-and-directories}

Le navigateur d'arborescence de fichiers affiche la structure de votre dépôt avec les fichiers et répertoires que vous pouvez développer et réduire.

Pour naviguer dans le navigateur d'arborescence de fichiers :

1. Dans le coin supérieur gauche, sélectionnez l'icône du navigateur d'arborescence de fichiers ({{< icon name="file-tree" >}}).
1. Pour développer un répertoire, sélectionnez {{< icon name="chevron-right" >}} à côté du nom du répertoire.
1. Pour afficher un fichier, sélectionnez le nom du fichier.

Lorsque vous accédez directement à un fichier imbriqué, le navigateur d'arborescence de fichiers développe automatiquement les répertoires parents et met en surbrillance le fichier actuel.

## Rechercher des fichiers {#search-files}

Utilisez le panneau de recherche pour trouver des fichiers par nom dans votre dépôt.

Pour rechercher des fichiers :

1. Dans le coin supérieur gauche, sélectionnez l'icône du navigateur d'arborescence de fichiers ({{< icon name="file-tree" >}}).
1. Pour ouvrir le panneau de recherche, sélectionnez **Rechercher des fichiers**.
1. Saisissez une partie du nom du fichier que vous souhaitez trouver. La liste des résultats affiche les fichiers correspondants et leurs répertoires parents.
1. Sélectionnez le fichier vers lequel vous souhaitez accéder.

Si aucun fichier ne correspond à votre recherche, la recherche affiche **Aucun résultat trouvé**.

## Raccourcis clavier {#keyboard-shortcuts}

Le navigateur d'arborescence de fichiers prend en charge les raccourcis clavier suivants :

| Raccourci                      | Action |
|-------------------------------|--------|
| <kbd>Shift</kbd>+<kbd>F</kbd> | Afficher ou masquer le navigateur d'arborescence de fichiers. |
| <kbd>F</kbd>                  | Ouvrir le panneau de recherche. |

Pour obtenir la liste complète des raccourcis clavier disponibles, consultez [Raccourcis clavier GitLab](../../../shortcuts.md).

### Navigation dans l'arborescence {#tree-navigation}

Le navigateur d'arborescence de fichiers implémente le [modèle treeview W3C ARIA](https://www.w3.org/WAI/ARIA/apg/patterns/treeview/) pour la navigation au clavier :

| Touche                                                  | Fonction |
|------------------------------------------------------|----------|
| <kbd>Entrée</kbd> ou <kbd>Espace</kbd>                 | Sélectionner le fichier ou répertoire actif |
| <kbd>Flèche vers le bas</kbd>                                | Déplacer le focus vers le fichier ou répertoire suivant sans ouvrir ni fermer les répertoires. Ne fait rien si le focus est sur le dernier élément. |
| <kbd>Flèche vers le haut</kbd>                                  | Déplacer le focus vers le fichier ou répertoire précédent sans ouvrir ni fermer les répertoires. Ne fait rien si le focus est sur le premier élément. |
| <kbd>Flèche vers la droite</kbd>                               | Lorsque le focus est sur un répertoire fermé, l'ouvre. Lorsque le focus est sur un répertoire ouvert, déplace le focus vers le premier élément à l'intérieur. Ne fait rien si le focus est sur un fichier. |
| <kbd>Flèche vers la gauche</kbd>                                | Lorsque le focus est sur un répertoire ouvert, le ferme. Lorsque le focus est sur un fichier ou un élément imbriqué, déplace le focus vers son répertoire parent. Ne fait rien si le focus est sur un répertoire racine fermé. |
| <kbd>Début</kbd>[^home-end-keys]                                     | Déplacer le focus vers le premier fichier ou répertoire sans ouvrir ni fermer les répertoires. |
| <kbd>Fin</kbd>[^home-end-keys]                                       | Déplacer le focus vers le dernier fichier ou répertoire sans développer les répertoires fermés. |
| <kbd>a</kbd>-<kbd>z</kbd>, <kbd>A</kbd>-<kbd>Z</kbd> | Déplacer le focus vers le fichier ou répertoire suivant dont le nom commence par le caractère saisi. La recherche revient au premier élément si aucune correspondance n'est trouvée. Ignore les éléments à l'intérieur des répertoires fermés. |
| <kbd>\*</kbd> (astérisque)                              | Développer tous les répertoires fermés au même niveau que l'élément actif. Le focus ne se déplace pas. |

[^home-end-keys]: les touches <kbd>Début</kbd> et <kbd>Fin</kbd> peuvent ne pas être disponibles sur tous les claviers.

## Sujets connexes {#related-topics}

- [Éditeur web](../web_editor.md)
- [Historique des fichiers Git](git_history.md)
- [Blame de fichiers Git](git_blame.md)
