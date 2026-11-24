---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Empêchez la fusion d'une merge request incomplète jusqu'à ce qu'elle soit prête en la définissant comme brouillon."
title: Merge requests en brouillon
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si une merge request n'est pas prête à être fusionnée, vous pouvez bloquer sa fusion jusqu'à ce que vous [la marquiez comme prête](#mark-merge-requests-as-ready). Les merge requests marquées comme **Brouillon** ne peuvent pas être fusionnées tant que vous n'avez pas supprimé le drapeau **Brouillon**, même si elles remplissent tous les autres critères de fusion :

![Une merge request affichant le statut brouillon avec la fusion bloquée jusqu'à ce qu'elle soit marquée comme prête.](img/merge_request_draft_blocked_v16_0.png)

## Marquer les merge requests comme brouillons {#mark-merge-requests-as-drafts}

Vous pouvez marquer une merge request comme brouillon de plusieurs façons :

- Affichage d'une merge request : dans le coin supérieur droit de la merge request, sélectionnez **Actions de requête de fusion** ({{< icon name="ellipsis_v" >}}), puis **Marquer comme brouillon**.
- Création ou modification d'une merge request : Vous pouvez procéder de l'une des manières suivantes :
  - Ajoutez `[Draft]`, `Draft:` ou `(Draft)` au début du titre de la merge request.
  - Sélectionnez **Marquer comme brouillon** sous le champ **Intitulé**.
- Ajout d'un commentaire dans une merge request existante : ajoutez l'[action rapide `/draft`](../quick_actions.md#draft) dans un commentaire. Pour marquer une merge request comme prête, utilisez l'action rapide [`/ready`](../quick_actions.md#ready).
- Création d'un commit : ajoutez `draft:`, `Draft:`, `fixup!` ou `Fixup!` au début d'un message de commit ciblant la branche source de la merge request. Cette méthode n'est pas une bascule. Ajouter à nouveau ce texte dans un commit ultérieur ne marque pas la merge request comme prête.

## Marquer les merge requests comme prêtes {#mark-merge-requests-as-ready}

Lorsqu'une merge request est prête à être fusionnée, vous pouvez supprimer le drapeau `Draft` de plusieurs façons :

- Affichage d'une merge request : dans le coin supérieur droit de la merge request, sélectionnez **Marquer comme prêt**. Les utilisateurs disposant du rôle Developer, Maintainer ou Owner peuvent également faire défiler la description de la merge request jusqu'en bas et sélectionner **Marquer comme prêt**.
- Modification d'une merge request existante : supprimez `[Draft]`, `Draft:` ou `(Draft)` du début du titre, ou décochez **Marquer comme brouillon** sous le champ **Intitulé**.
- Ajout d'un commentaire dans une merge request existante : ajoutez l'[action rapide `/ready`](../quick_actions.md#ready) dans un commentaire de la merge request.

Lorsque vous marquez une merge request comme prête, GitLab notifie les [participants et observateurs de la merge request](../../profile/notifications.md#issue-merge-request-and-epic-events).

## Inclure ou exclure les brouillons lors d'une recherche {#include-or-exclude-drafts-when-searching}

Lorsque vous consultez ou effectuez une recherche dans la liste des merge requests de votre projet, pour inclure ou exclure les merge requests en brouillon :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**.
1. Pour filtrer par statut de merge request, sélectionnez **Ouvrir**, **Fusionnées**, **Fermé** ou **Tous** dans la barre de navigation.
1. Sélectionnez la zone de recherche pour afficher une liste de filtres et sélectionnez **Brouillon**, ou saisissez le mot `draft`.
1. Sélectionnez `=`.
1. Sélectionnez **Oui** pour inclure les brouillons, ou **Non** pour les exclure, puis appuyez sur **Entrée** pour mettre à jour la liste des merge requests :

   ![La liste déroulante de filtres des merge requests affichant les options de filtre de brouillon avec les options de sélection.](img/filter_draft_merge_requests_v16_0.png)

## Pipelines pour les brouillons {#pipelines-for-drafts}

Les merge requests en brouillon exécutent les mêmes pipelines que les merge requests marquées comme prêtes.

Pour ignorer un pipeline pour une merge request en brouillon, consultez [ignorer les pipelines pour les merge requests en brouillon](../../../ci/yaml/workflow.md#skip-pipelines-for-draft-merge-requests).
