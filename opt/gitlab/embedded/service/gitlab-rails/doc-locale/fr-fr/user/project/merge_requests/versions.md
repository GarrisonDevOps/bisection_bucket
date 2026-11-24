---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Utilisez les versions de diff pour comparer les pushs contenus dans une seule merge request.
title: Versions de diff de merge request
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lorsque vous créez une merge request, vous sélectionnez deux branches à comparer. Les différences entre les deux branches sont affichées sous forme de diff dans la merge request. Chaque fois que vous poussez des commits vers une branche connectée à une merge request, GitLab met à jour le diff de la merge request vers une nouvelle version de diff.

> [!note]
> Les versions de diff sont mises à jour à chaque push, et non à chaque commit. Si un push contient plusieurs commits, une seule nouvelle version de diff est créée.

Par défaut, GitLab compare le dernier push de votre branche source (`feature`) avec le commit le plus récent de la branche cible, souvent `main`.

## Comparer les versions de diff {#compare-diff-versions}

Si vous avez poussé vers votre branche plusieurs fois, la version de diff de chaque push précédent est disponible pour la comparaison. Lorsque votre merge request contient de nombreuses modifications ou des modifications séquentielles sur le même fichier, vous pouvez souhaiter comparer un nombre plus restreint de modifications.

Prérequis :

- La branche de la merge request doit contenir des commits issus de plusieurs pushs. Les commits individuels d'un même push ne génèrent pas de nouvelles versions de diff.

Pour comparer des versions de diff :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**.
1. Sélectionnez une merge request.
1. Pour afficher la version de diff actuelle de cette merge request, sélectionnez **Modifications**.
1. À côté de **Comparer** ({{< icon name="file-tree" >}}), sélectionnez les pushs à comparer. Cet exemple compare `main` avec le push le plus récent (dernière version de diff) de la branche :

   ![Liste déroulante des versions de merge request](img/versions_dropdown_v16_6.png)

   Cette branche exemple comporte quatre commits, mais la branche ne contient que trois versions de diff car deux commits ont été poussés en même temps.

## Afficher les versions de diff depuis une note système {#view-diff-versions-from-a-system-note}

GitLab ajoute une note système à une merge request chaque fois que vous poussez de nouvelles modifications vers la branche de la merge request. Dans cet exemple, un seul push a ajouté deux commits :

![Note système des versions de merge request](img/versions_system_note_v16_6.png)

Pour afficher le diff de ce commit, sélectionnez le SHA du commit.

Pour plus d'informations, consultez comment [afficher ou filtrer les notes système d'une merge request](../system_notes.md#on-a-merge-request).

## Sujets connexes {#related-topics}

- [Stockage des diffs de merge request pour les administrateurs](../../../administration/merge_request_diffs.md)
