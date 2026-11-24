---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Comment créer une merge request pour un ticket confidentiel sans divulguer publiquement des informations.
title: Merge requests pour les tickets confidentiels
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les merge requests dans un dépôt public sont également publiques, même lorsque vous créez une merge request pour un [ticket confidentiel](../issues/confidential_issues.md). Pour éviter de divulguer des informations confidentielles lorsque vous travaillez sur un ticket confidentiel, créez votre merge request depuis une duplication privée dans le même espace de nommage.

Les rôles sont hérités des groupes parents. Si vous créez votre duplication privée dans le même espace de nommage (même groupe ou sous-groupe) que le dépôt original (public), les développeurs reçoivent les mêmes autorisations dans votre duplication. Cet héritage garantit que :

- Les utilisateurs ayant le rôle Developer disposent des autorisations nécessaires pour consulter les tickets confidentiels et les résoudre.
- Vous n'avez pas besoin d'accorder à chaque utilisateur individuellement l'accès à votre duplication.

Pour plus d'informations, consultez le [runbook de release de correctifs pour les ingénieurs GitLab](https://gitlab.com/gitlab-org/release/docs/blob/master/general/security/engineer.md).

## Créer une merge request confidentielle {#create-a-confidential-merge-request}

Les branches sont publiques par défaut. Pour protéger la confidentialité de votre travail, vous devez créer vos branches et vos merge requests dans le même espace de nommage, mais en aval dans une duplication privée. Si vous créez votre duplication privée dans le même espace de nommage que le dépôt public, votre duplication hérite des autorisations du dépôt public en amont. Les utilisateurs ayant le rôle Developer pour le dépôt public en amont héritent de ces autorisations en amont dans votre duplication privée en aval, sans aucune action de votre part. Ces utilisateurs peuvent immédiatement pousser du code vers des branches dans votre duplication privée pour aider à résoudre le ticket confidentiel.

> [!warning]
> Votre duplication privée peut exposer des informations confidentielles si vous la créez dans un espace de nommage différent de celui du dépôt en amont. Les deux espaces de nommage peuvent ne pas contenir les mêmes utilisateurs.

Prérequis :

- Vous avez le rôle Maintainer ou Owner pour le dépôt public, car vous avez besoin de l'un de ces rôles pour [créer un sous-groupe](../../group/subgroups/_index.md).
- Vous avez [dupliqué](../repository/forking_workflow.md) le dépôt public.
- Votre duplication a un **Niveau de visibilité** défini sur **Privé**.

Pour créer une merge request confidentielle :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**, puis filtrez par **Type** = **Ticket** et sélectionnez votre ticket.
1. Faites défiler la page sous la description du ticket, puis sélectionnez **Créer une requête de fusion confidentielle**.
1. Sélectionnez l'option qui correspond à vos besoins :
   - Pour créer à la fois une branche et une merge request, sélectionnez **Créer une requête de fusion confidentielle et une branche**. Votre merge request cible la branche par défaut de votre duplication, et non la branche par défaut du projet public en amont.
   - Pour créer uniquement une branche, sélectionnez **Créer une branche**.
1. Sélectionnez un **Projet** à utiliser. Ces projets ont les merge requests activées, et vous y disposez du rôle Developer (ou supérieur).
1. Indiquez un **Nom de la branche**, puis sélectionnez une **Source (branche ou étiquette)**. GitLab vérifie si ces branches sont disponibles dans votre duplication privée, car les deux branches doivent être disponibles dans la duplication sélectionnée.
1. Sélectionnez **Créer**.

Cette merge request cible votre duplication privée, et non le projet public en amont. Votre branche, vos merge requests et vos commits restent dans votre duplication privée. Cela évite de divulguer prématurément des informations confidentielles.

Ouvrez une merge request [depuis votre duplication vers le dépôt en amont](../repository/forking_workflow.md#merge-changes-back-upstream) lorsque :

- Vous estimez que le problème est résolu dans votre duplication privée.
- Vous êtes prêt à rendre les commits confidentiels publics.

## Sujets connexes {#related-topics}

- [Tickets confidentiels](../issues/confidential_issues.md)
- [Rendre un epic confidentiel](../../group/epics/manage_epics.md#make-an-epic-confidential)
- [Ajouter une note interne](../../discussions/_index.md#add-an-internal-note)
- [Pratiques de sécurité pour les merge requests confidentielles](https://gitlab.com/gitlab-org/release/docs/blob/master/general/security/engineer.md#security-releases-critical-non-critical-as-a-developer) chez GitLab
