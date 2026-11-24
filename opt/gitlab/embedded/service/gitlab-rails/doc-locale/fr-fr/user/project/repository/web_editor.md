---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Utilisez l'éditeur Web pour créer, téléverser et modifier des fichiers texte directement dans l'interface utilisateur de GitLab."
title: Éditeur Web
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

L'éditeur Web est un outil basé sur le navigateur permettant d'apporter des modifications à vos dépôts GitLab sans configuration locale. Vous pouvez :

- Modifier des fichiers individuels et prévisualiser vos modifications avant de les valider.
- Créer de nouveaux fichiers et répertoires.
- Téléverser et remplacer des fichiers.
- Créer des branches et des étiquettes pour le contrôle de version.
- [Verrouiller des fichiers](../file_lock.md#lock-a-file-or-directory) pour éviter les conflits lors d'éditions simultanées.
- Contribuer à des projets sans configurer Git localement.

GitLab utilise votre [adresse e-mail principale](../../profile/_index.md#change-the-email-displayed-on-your-commits) pour les commits de l'éditeur Web.

Pour apporter des modifications à plusieurs fichiers, utilisez le [Web IDE](../web_ide/_index.md).

> [!note]
> Pour gérer des fichiers dans une [branche protégée](branches/protected.md), vous devez disposer des [permissions](../../permissions.md) appropriées.

## Gérer les fichiers {#manage-files}

Vous pouvez créer, modifier, téléverser et supprimer des fichiers avec l'éditeur Web, directement depuis l'interface utilisateur de GitLab.

### Créer un fichier {#create-a-file}

Pour créer un fichier texte dans l'éditeur Web :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez au répertoire dans lequel vous souhaitez créer le nouveau fichier.
1. À côté du nom du répertoire, sélectionnez l'icône plus ({{< icon name="plus" >}}) > **Nouveau fichier**.
1. À côté du nom de la branche, saisissez un nom de fichier et une extension. Par exemple, `my_file.md`.
1. Ajoutez du contenu à votre fichier.
1. Sélectionnez **Valider les modifications**.
1. Dans le champ **Message de commit**, saisissez une raison pour le commit.
1. Choisissez l'une des options suivantes :

   - Pour créer un fichier dans la branche cible préremplie, sélectionnez **Valider les modifications**.
   - Pour créer un fichier dans une nouvelle branche et valider les modifications :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est décochée.
     1. Sélectionnez **Valider les modifications**.

   - Pour créer un fichier dans une nouvelle branche, valider les modifications et créer une merge request :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est cochée.
     1. Sélectionnez **Valider les modifications**.

Pour ouvrir un nouvel éditeur de fichier avec un contenu prérempli, utilisez le paramètre de requête `content` dans l'URL. Par exemple :

```plaintext
https://gitlab.com/<your-namespace>/<your-project>/-/new/main?content=your+content+here
```

#### À partir d'un modèle {#from-a-template}

Pour créer un fichier texte à partir d'un modèle dans l'éditeur Web :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez au répertoire dans lequel vous souhaitez créer le nouveau fichier.
1. À côté du nom du répertoire, sélectionnez l'icône plus ({{< icon name="plus" >}}) > **Nouveau fichier**.
1. Dans **Nom du fichier**, saisissez un nom pour lequel GitLab fournit un modèle :
   - `.gitignore`
   - `.gitlab-ci.yml`
   - `LICENSE`
   - `Dockerfile`
1. Dans la liste déroulante **Appliquer un modèle**, sélectionnez un modèle.
1. Facultatif. Mettez à jour le modèle selon vos besoins.
1. Reprenez à partir de l'étape 6 du processus [créer un fichier](#create-a-file).

### Modifier un fichier {#edit-a-file}

Pour modifier un fichier texte dans l'éditeur Web :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez au fichier que vous souhaitez modifier.
1. Sélectionnez **Édition** > **Modifier un seul fichier**.
1. Effectuez vos modifications.
1. Sélectionnez **Valider les modifications**.
1. Dans le champ **Message de commit**, saisissez une raison pour le commit.
1. Choisissez l'une des options suivantes :

   - Pour modifier un fichier depuis la branche cible préremplie, sélectionnez **Valider les modifications**.
   - Pour modifier un fichier depuis une nouvelle branche et valider les modifications :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est décochée.
     1. Sélectionnez **Valider les modifications**.

   - Pour modifier un fichier depuis une nouvelle branche, valider les modifications et créer une merge request :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est cochée.
     1. Sélectionnez **Valider les modifications**.
     1. Remplissez les champs et sélectionnez **Créer une requête de fusion**.

> [!note]
> Si quelqu'un modifie et valide des modifications dans le même fichier pendant que vous l'éditez, vous ne pouvez pas valider vos modifications. Le message d'erreur suivant s'affiche : `Someone edited the file the same time you did. Please check out the file and
> make sure your change will not unintentionally remove theirs.`

#### Lien vers des lignes spécifiques {#link-to-specific-lines}

Pour créer un lien vers une ou plusieurs lignes dans l'éditeur Web, ajoutez des informations de hachage au segment du nom de fichier dans l'URL. Par exemple :

- `MY_FILE.js#L3` met en évidence la ligne 3 dans `MY_FILE.js`.
- `MY_FILE.js#L3-10` met en évidence les lignes 3 à 10 dans `MY_FILE.js`.

Lorsque vous modifiez un fichier, vous pouvez également créer un lien vers une seule ligne en sélectionnant un numéro de ligne.

#### Modifier des fichiers dans une merge request dupliquée {#edit-files-in-a-forked-merge-request}

Prérequis :

- Vous devez travailler sur une merge request depuis une duplication.
- [Autoriser les commits des membres en amont](../merge_requests/allow_collaboration.md#allow-commits-from-upstream-members) doit être activé.

Si vous travaillez sur une merge request depuis un projet dupliqué, vous pouvez modifier un fichier et valider des modifications. Pour cela :

1. Accédez à la merge request.
1. Accédez au fichier que vous souhaitez modifier.
1. Sélectionnez **Édition** > **Modifier un seul fichier**.
1. Sélectionnez **Valider les modifications**.
1. Dans **Message de commit**, saisissez une raison pour le commit. Les informations suivantes sont fournies : `Your changes can be committed to <branch-name> because a merge request is open.`
1. Sélectionnez **Valider les modifications**.

### Prévisualiser un fichier {#preview-a-file}

{{< history >}}

- La prévisualisation des nouveaux fichiers a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253963) dans GitLab 19.4.

{{< /history >}}

Lorsque vous créez ou modifiez un fichier dans l'éditeur Web, vous pouvez prévisualiser votre contenu avant de le valider.

Pour prévisualiser votre contenu, sélectionnez l'onglet **Aperçu**. Ce que vous voyez dépend de l'extension du fichier :

- Les fichiers Markdown affichent un aperçu en direct à côté de votre contenu, qui se met à jour au fur et à mesure que vous tapez.
- Les autres fichiers de balisage, tels qu'AsciiDoc, Org et reStructuredText, affichent le balisage rendu.
- Tous les autres fichiers affichent un diff de vos modifications.

Pour revenir à votre contenu, sélectionnez l'onglet **Écrire**.

Lorsque vous modifiez un fichier qui n'est pas un fichier de balisage, l'onglet est intitulé **Aperçu des modifications**.

### Téléverser un fichier {#upload-a-file}

Pour téléverser un fichier dans l'éditeur Web :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez au répertoire dans lequel vous souhaitez téléverser le fichier.
1. À côté du nom du répertoire, sélectionnez l'icône plus ({{< icon name="plus" >}}) > **Téléverser un fichier**.
1. Déposez ou téléversez le fichier que vous souhaitez ajouter.
1. Dans le champ **Message de commit**, saisissez une raison pour le commit.
1. Choisissez l'une des options suivantes :

   - Pour téléverser un fichier depuis la branche cible préremplie, sélectionnez **Valider les modifications**.
   - Pour téléverser un fichier depuis une nouvelle branche et valider les modifications :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est décochée.
     1. Sélectionnez **Valider les modifications**.

   - Pour téléverser un fichier depuis une nouvelle branche, valider les modifications et créer une merge request :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est cochée.
     1. Sélectionnez **Valider les modifications**.
     1. Remplissez les champs et sélectionnez **Créer une requête de fusion**.

### Supprimer un fichier {#delete-a-file}

Pour supprimer un fichier dans l'éditeur Web :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez au fichier que vous souhaitez supprimer.
1. Sélectionnez **Supprimer**.
1. Dans **Message de commit**, saisissez une raison pour le commit.
1. Choisissez parmi les options suivantes :

   - Pour supprimer un fichier depuis la branche cible préremplie, sélectionnez **Valider les modifications**.
   - Pour supprimer un fichier depuis une nouvelle branche et valider les modifications :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est décochée.
     1. Sélectionnez **Valider les modifications**.

   - Pour supprimer un fichier depuis une nouvelle branche, valider les modifications et créer une merge request :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est cochée.
     1. Sélectionnez **Valider les modifications**.

> [!note]
> Si quelqu'un modifie et valide des modifications dans le même fichier pendant que vous l'éditez, vous ne pouvez pas valider vos modifications. Le message d'erreur suivant s'affiche : `Someone edited the file the same time you did. Please check out the file and
> make sure your change will not unintentionally remove theirs.`

### Remplacer un fichier {#replace-a-file}

Pour remplacer un fichier dans l'éditeur Web :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez au fichier que vous souhaitez remplacer.
1. Sélectionnez **Remplacer**.
1. Déposez ou téléversez le fichier que vous souhaitez téléverser et remplacer l'existant.
1. Dans **Message de commit**, saisissez une raison pour le commit.
1. Choisissez parmi les options suivantes :

   - Pour remplacer un fichier depuis la branche cible préremplie, sélectionnez **Valider les modifications**.
   - Pour remplacer un fichier depuis une nouvelle branche et valider les modifications :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est décochée.
     1. Sélectionnez **Valider les modifications**.

   - Pour remplacer un fichier depuis une nouvelle branche, valider les modifications et créer une merge request :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est cochée.
     1. Sélectionnez **Valider les modifications**.

### Annuler les modifications d'un fichier {#cancel-file-changes}

Pour annuler des modifications, modifier, téléverser ou supprimer un fichier depuis l'éditeur Web :

1. Sélectionnez **Annuler**.
1. Sélectionnez l'une des options suivantes :

   - Confirmez que vous souhaitez annuler les modifications : sélectionnez **OK**.
   - Ne pas annuler les modifications : Sélectionnez **Annuler**.

### Opérations sur les fichiers depuis le menu Actions {#file-operations-from-the-actions-menu}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/519325) dans GitLab 17.10 [avec le feature flag](../../../administration/feature_flags/_index.md) `blob_overflow_menu`. Fonctionnalité désactivée par défaut.
- [En disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/522993) dans GitLab 18.1. Suppression du feature flag `blob_overflow_menu`.

{{< /history >}}

Le menu **Actions** ({{< icon name="ellipsis_v" >}}) regroupe les opérations sur les fichiers dans la liste déroulante. Depuis ce menu, vous pouvez :

- Modifier un fichier.
- Téléverser un fichier.
- Supprimer un fichier.
- Remplacer un fichier.

Pour effectuer ces actions :

1. Ouvrez le fichier dans GitLab.
1. Dans le coin supérieur droit, à côté d'un nom de fichier, sélectionnez **Actions** ({{< icon name="ellipsis_v" >}}).
1. Sélectionnez l'action souhaitée.

## Créer un répertoire {#create-a-directory}

Pour créer un répertoire dans l'éditeur Web :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez au répertoire dans lequel vous souhaitez créer le nouveau répertoire.
1. À côté du nom du répertoire, sélectionnez l'icône plus ({{< icon name="plus" >}}) > **Nouveau répertoire**.
1. Dans le champ **Nom du répertoire**, saisissez le nom de votre répertoire.
1. Dans **Message de commit**, saisissez une raison pour le commit.
1. Choisissez parmi les options suivantes :

   - Pour créer un répertoire depuis la branche cible préremplie, sélectionnez **Valider les modifications**.
   - Pour créer un répertoire depuis une nouvelle branche et valider les modifications :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est décochée.
     1. Sélectionnez **Valider les modifications**.

   - Pour créer un répertoire depuis une nouvelle branche, valider les modifications et créer une merge request :

     1. Sélectionnez **Valider dans une nouvelle branche**.
     1. Saisissez un nom de branche.
     1. Assurez-vous que la case **Créer une requête de fusion pour cette modification** est cochée.
     1. Sélectionnez **Valider les modifications**.

## Créer une branche {#create-a-branch}

Pour créer une [branche](branches/_index.md) dans l'éditeur Web :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. À côté du nom du dépôt, sélectionnez l'icône plus ({{< icon name="plus" >}}) > **Nouvelle branche**.
1. Remplissez les champs.
1. Sélectionnez **Créer une branche**.

## Créer une étiquette {#create-a-tag}

Vous pouvez créer des [étiquettes](tags/_index.md) pour marquer des jalons tels que les releases de production et les release candidates. Pour créer une étiquette dans l'éditeur Web :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. À côté du nom du dépôt, sélectionnez l'icône plus ({{< icon name="plus" >}}) > **Nouvelle étiquette**.
1. Remplissez les champs.
1. Sélectionnez **Créer une étiquette**.

## Options d'accessibilité de l'éditeur {#editor-accessibility-options}

L'éditeur Web est basé sur l'[éditeur Monaco](https://github.com/microsoft/monaco-editor), qui dispose de plusieurs [fonctionnalités d'accessibilité](https://github.com/microsoft/monaco-editor/wiki/Monaco-Editor-Accessibility-Guide), notamment :

| Fonctionnalité                          | Raccourci sur Windows ou Linux      | Raccourci sur macOS                                    | Détails |
|----------------------------------|-----------------------------------|------------------------------------------------------|---------|
| Liste des commandes de navigation au clavier | <kbd>F1</kbd>                     | <kbd>F1</kbd>                                        | Une [liste de commandes](https://github.com/microsoft/monaco-editor/wiki/Monaco-Editor-Accessibility-Guide#keyboard-navigation) qui facilitent l'utilisation de l'éditeur sans souris. |
| Piégeage de tabulation                     | <kbd>Control</kbd>+<kbd>m</kbd> | <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>m</kbd> | Activez le [piégeage de tabulation](https://github.com/microsoft/monaco-editor/wiki/Monaco-Editor-Accessibility-Guide#tab-trapping) pour passer à l'élément suivant pouvant recevoir le focus sur la page au lieu d'insérer un caractère de tabulation. |

## Sujets connexes {#related-topics}

- [Créer des merge requests](../merge_requests/creating_merge_requests.md)
- [Branches](branches/_index.md)
  - [Branche par défaut](branches/default.md)
  - [Branches protégées](branches/protected.md)
- [Web IDE](../web_ide/_index.md)
- [Navigateur d'arborescence de fichiers](files/file_tree_browser.md)
