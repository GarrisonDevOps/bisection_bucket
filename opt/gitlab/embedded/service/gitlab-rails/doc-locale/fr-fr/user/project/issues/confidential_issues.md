---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Tickets confidentiels
description: "Activez la confidentialité d'un ticket pour limiter sa visibilité aux membres du projet disposant au minimum du rôle Planificateur."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les tickets confidentiels sont des [tickets](_index.md) visibles uniquement par les membres d'un projet disposant des [autorisations suffisantes](#who-can-see-confidential-issues). Les tickets confidentiels peuvent être utilisés aussi bien par des projets open source que par des entreprises pour garder les vulnérabilités de sécurité privées ou éviter que des informations ne filtrent.

## Rendre un ticket confidentiel {#make-an-issue-confidential}

{{< history >}}

- Le rôle minimum requis pour rendre un ticket confidentiel a [été modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Vous pouvez rendre un ticket confidentiel lors de sa création ou de sa modification.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet afin de convertir un ticket existant en ticket confidentiel.
- Si le ticket que vous souhaitez rendre confidentiel possède des [tâches](../../tasks.md) enfants, vous devez d'abord rendre toutes les tâches enfants confidentielles. Un ticket confidentiel ne peut avoir que des éléments enfants confidentiels.

### Dans un nouveau ticket {#in-a-new-issue}

Lorsque vous créez un nouveau ticket, une case à cocher située juste en dessous de la zone de texte vous permet de marquer le ticket comme confidentiel. Cochez cette case et sélectionnez **Créer un ticket** pour créer le ticket.

Lorsque vous créez un ticket confidentiel dans un projet, celui-ci apparaît dans la section **A contribué aux projets** de votre [profil](../../profile/_index.md). **A contribué aux projets** n'affiche aucune information sur le ticket confidentiel. Seul le nom du projet est affiché.

Pour créer un ticket confidentiel :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}).
1. Dans la liste déroulante, sélectionnez **Nouveau ticket**.
1. Renseignez les [champs](create_issues.md#fields-in-the-new-issue-form).
   - Cochez la case **Activer la confidentialité**.
1. Sélectionnez **Créer un ticket**.

### Dans un ticket existant {#in-an-existing-issue}

Pour modifier la confidentialité d'un ticket existant :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**, puis filtrez par **Type** = **Ticket** et sélectionnez votre ticket.
1. Dans le coin supérieur droit, sélectionnez **Actions du ticket** ({{< icon name="ellipsis_v" >}}) puis **Activer la confidentialité** (ou **Désactiver la confidentialité** pour rendre le ticket non confidentiel).

Vous pouvez également utiliser l'[action rapide `/confidential`](../quick_actions.md#confidential).

## Qui peut voir les tickets confidentiels {#who-can-see-confidential-issues}

{{< history >}}

- Le rôle minimum requis pour voir les tickets confidentiels a [été modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256) de Reporter à Planificateur dans GitLab 17.7.

{{< /history >}}

Lorsqu'un ticket est rendu confidentiel, seuls les utilisateurs disposant du rôle Planificateur, Reporter, Developer, Maintainer ou Owner pour le projet ont accès au ticket. Les utilisateurs disposant du rôle Invité ou du rôle [Minimal](../../permissions.md#users-with-minimal-access) ne peuvent pas accéder au ticket, même s'ils y participaient activement avant la modification.

Toutefois, un utilisateur disposant du **rôle Invité** peut créer des tickets confidentiels, mais ne peut consulter que ceux qu'il a créés lui-même.

Les utilisateurs disposant du rôle Invité ou les non-membres peuvent lire le ticket confidentiel s'ils y sont assignés. Lorsqu'un utilisateur Invité ou un non-membre est désassigné d'un ticket confidentiel, il ne peut plus le consulter.

Les tickets confidentiels sont masqués dans les résultats de recherche pour les utilisateurs ne disposant pas des autorisations nécessaires.

## Indicateurs de ticket confidentiel {#confidential-issue-indicators}

Les tickets confidentiels se distinguent visuellement des tickets ordinaires de plusieurs façons. Dans les pages **Tickets** et **Tableaux des tickets**, vous pouvez voir l'icône de confidentialité ({{< icon name="eye-slash" >}}) à côté des tickets marqués comme confidentiels.

Si vous ne disposez pas des [autorisations suffisantes](#who-can-see-confidential-issues), vous ne pouvez pas voir les tickets confidentiels du tout.

De même, lorsque vous êtes dans le ticket, vous pouvez voir l'icône de confidentialité ({{< icon name="eye-slash" >}}) juste à côté du numéro du ticket. Un indicateur apparaît également dans la zone de commentaire pour signaler que le ticket sur lequel vous commentez est confidentiel.

Un indicateur de confidentialité est également présent dans la barre latérale.

Chaque passage de l'état ordinaire à l'état confidentiel, et inversement, est signalé par une note système dans les commentaires du ticket, par exemple :

- {{< icon name="eye-slash" >}} Jo Garcia a rendu le ticket confidentiel il y a 5 minutes
- {{< icon name="eye" >}} Jo Garcia a rendu le ticket visible par tous à l'instant

## Merge requests pour les tickets confidentiels {#merge-requests-for-confidential-issues}

Bien que vous puissiez créer des tickets confidentiels (et rendre des tickets existants confidentiels) dans un projet public, vous ne pouvez pas créer de merge requests confidentielles. Découvrez comment créer des [merge requests pour les tickets confidentiels](../merge_requests/confidential.md) afin d'éviter toute fuite de données privées.

## Sujets connexes {#related-topics}

- [Merge requests pour les tickets confidentiels](../merge_requests/confidential.md)
- [Rendre un epic confidentiel](../../group/epics/manage_epics.md#make-an-epic-confidential)
- [Ajouter une note interne](../../discussions/_index.md#add-an-internal-note)
- [Bonnes pratiques de sécurité pour les merge requests confidentielles](https://gitlab.com/gitlab-org/release/docs/blob/master/general/security/engineer.md#security-releases-critical-non-critical-as-a-developer) chez GitLab
