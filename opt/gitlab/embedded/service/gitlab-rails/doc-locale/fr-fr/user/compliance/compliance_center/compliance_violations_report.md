---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Explorez le rapport sur les violations de conformité de GitLab pour afficher et gérer les problèmes de non-conformité dans vos projets et groupes.
title: Rapport sur les violations de conformité
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Rapport dynamique sur les violations de conformité
  - [Introduit](https://gitlab.com/groups/gitlab-org/-/epics/12774) dans GitLab 18.2 [avec des feature flags](../../../administration/feature_flags/_index.md) nommés `compliance_violations_report` et `enable_project_compliance_violations`. Fonctionnalité désactivée par défaut.
  - [Activé sur GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/201027) dans GitLab 18.3.
  - [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/201027) dans GitLab 18.5. Les feature flags `compliance_violations_report` et `enable_project_compliance_violations` ont été supprimés.

{{< /history >}}

Utilisez le rapport sur les violations de conformité pour obtenir une vue complète des violations de conformité dans tous les projets de votre groupe. Le rapport fournit des informations détaillées sur les contrôles compromis, les événements d'audit associés, et vous permet de gérer les statuts des violations.

## Activer le rapport sur les violations de conformité {#enable-compliance-violations-report}

Avant que les violations n'apparaissent dans le rapport sur les violations de conformité, vous devez :

1. [Créer un cadre de conformité avec des contrôles](../compliance_frameworks/_index.md).
1. [Appliquer le cadre à vos projets](../compliance_frameworks/_index.md#apply-a-compliance-framework-to-a-project).

Une fois ces étapes effectuées, les violations apparaissent dans le rapport sur les violations de conformité au fur et à mesure de leur détection.

Les violations sont automatiquement détectées lorsque des événements d'audit enfreignent les contrôles définis dans votre cadre. Le système surveille en permanence les événements d'audit et les compare aux définitions de contrôle de votre cadre afin d'identifier les non-conformités.

### Contrôles pris en charge {#supported-controls}

Les contrôles de conformité suivants sont pris en charge pour la détection des violations :

- `minimum_approvals_required_1`
- `minimum_approvals_required_2`
- `merge_request_prevent_author_approval`
- `merge_request_prevent_committers_approval`

Pour plus d'informations sur les contrôles de conformité, consultez [Cadres de conformité](../compliance_frameworks/_index.md).

## Afficher le rapport sur les violations de conformité {#view-the-compliance-violations-report}

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le projet ou le groupe.

Pour afficher le rapport sur les violations de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.

Le rapport sur les violations de conformité affiche :

- **Statut** : le statut actuel de la violation. Par exemple, À réviser, Résolue ou Ignorée.
- **Contrôle et cadre compromis** : le contrôle de conformité spécifique qui a été compromis et son cadre associé.
- **Événement d'audit** : Détails sur l'événement qui a déclenché la violation.
- **Projet** : le projet dans lequel la violation s'est produite.
- **Date détectée** : date à laquelle la violation a été identifiée.
- **Action** : lien permettant d'afficher des informations détaillées sur la violation.

Dans le rapport, vous pouvez :

- Trier le rapport en sélectionnant les en-têtes de colonnes.
- Modifier le statut des violations à l'aide de la liste déroulante des statuts.
- Naviguer dans les différentes pages de violations à l'aide de la pagination.
- Afficher des informations détaillées sur chaque violation.
- Exporter le rapport sous forme de fichier CSV.

### Filtrer les violations de conformité {#filter-compliance-violations}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/555541) dans GitLab 18.7.
- Les filtres **Détection avant** et **Détection après** ont été [introduits](https://gitlab.com/gitlab-org/gitlab/-/work_items/582497) dans GitLab 19.1.

{{< /history >}}

Vous pouvez filtrer le rapport sur les violations de conformité pour vous concentrer sur des violations spécifiques :

1. Dans le rapport sur les violations de conformité, utilisez les options de filtre en haut de la page.
1. Sélectionnez un ou plusieurs filtres :
   - **Statut** : filtrer par statut de violation (Détectée, Ignorée, En révision ou Résolue).
   - **Projet** : filtrer par projets spécifiques dans votre groupe.
   - **Contrôle** : filtrer par contrôle de conformité.
   - **Détection avant** : afficher les violations détectées avant une date spécifique.
   - **Détection après** : afficher les violations détectées à partir d'une date spécifique.

Combinez **Détection avant** et **Détection après** pour limiter le rapport à une plage de dates.

Le rapport se met à jour automatiquement pour n'afficher que les violations correspondant aux filtres sélectionnés.

Pour effacer les filtres, effacez les options de filtre ou sélectionnez **Effacer**.

## Détails des violations {#violation-details}

Lorsque vous sélectionnez **Détails** pour une violation spécifique, vous pouvez afficher :

- L'identifiant et le statut de la violation.
- L'emplacement (projet) où la violation s'est produite.
- Des informations complètes sur l'événement d'audit, notamment :
  - Auteur de l'événement.
  - Cible de l'événement.
  - Détails de l'événement.
  - Adresse IP.
  - Type de cible.
- Informations sur le contrôle compromis, notamment :
  - Nom et description du contrôle.
  - Cadre de conformité associé.
  - Exigences.
- Suggestions de correction avec des liens pour résoudre la violation.
- Commentaires et fils de discussion liés à la violation.

### Ajouter des commentaires aux violations {#add-comments-to-violations}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/541095) dans GitLab 18.7.

{{< /history >}}

Vous pouvez ajouter des commentaires aux violations pour collaborer avec votre équipe sur les efforts de remédiation :

1. Dans la vue des détails de la violation, faites défiler jusqu'à la section des commentaires.
1. Saisissez votre commentaire dans le champ de texte.
1. Sélectionnez **Commentaire** pour publier votre commentaire.

Votre commentaire est ajouté à la violation et visible par tous les utilisateurs ayant accès au rapport sur les violations de conformité.

## Gérer les statuts des violations {#manage-violation-statuses}

Vous pouvez mettre à jour le statut des violations de conformité pour suivre leur progression dans la remédiation. Les statuts disponibles sont les suivants :

- **À réviser** : statut par défaut pour les nouvelles violations
- **En cours** : la violation est en cours de traitement
- **Résolu** : la violation a été remédiée
- **Rejeté** : la violation a été examinée et ignorée

Pour modifier le statut d'une violation :

1. Dans le rapport sur les violations de conformité, localisez la violation que vous souhaitez mettre à jour.
1. Sélectionnez la liste déroulante du statut actuel dans la colonne **Statut**.
1. Choisissez le nouveau statut dans le menu de la liste déroulante.

Le statut est mis à jour immédiatement et reflété dans le rapport.

## Exporter le rapport sur les violations de conformité {#export-compliance-violations-report}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/551244) dans GitLab 18.3.

{{< /history >}}

Exportez un rapport CSV des violations de conformité pour tous les projets d'un groupe. Le rapport exporté comprend :

- Détecté le (DateTime, les plus récents en premier)
- Identifiant de la violation
- Statut
- Cadre
- Contrôle de conformité
- Exigence de conformité
- Auteur de l'événement d'audit
- Type d'événement d'audit
- Nom de l'événement d'audit
- Message de l'événement d'audit
- Identifiant du projet

Rapports :

- Sont tronqués à 15 Mo afin que la pièce jointe à l'e-mail ne soit pas trop volumineuse.
- Incluent toutes les violations, quels que soient les filtres actuellement appliqués à l'interface web.

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour exporter un rapport sur les violations de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Dans le coin supérieur droit, sélectionnez **Exporter**.
1. Sélectionnez **Exporter le rapport des violations**.

Un rapport est compilé et envoyé dans votre boîte de réception sous forme de pièce jointe.

## Rapport statique sur les violations de conformité {#static-compliance-violations-report}

> [!warning]
> Cette fonctionnalité a été [dépréciée](https://gitlab.com/gitlab-org/gitlab/-/issues/551236) dans GitLab 18.2 et sa suppression est prévue dans la version 18.8.

Le rapport statique sur les violations de conformité offre une vue de haut niveau de l'activité des merge requests pour tous les projets du groupe.

Lorsque vous sélectionnez une ligne dans le rapport statique sur les violations de conformité, un panneau latéral s'affiche et fournit :

- Le nom du projet et le [label du cadre de conformité](../../project/working_with_projects.md#add-a-compliance-framework-to-a-project), si le projet en a un d'assigné.
- Un lien vers la merge request qui a introduit la violation.
- Le chemin de branche de la merge request au format `[source] into [target]`.
- Une liste des utilisateurs ayant effectué des commits de modifications dans la merge request.
- Une liste des utilisateurs ayant commenté la merge request.
- Une liste des utilisateurs ayant approuvé la merge request.
- L'utilisateur ayant fusionné la merge request.

### Afficher le rapport statique sur les violations de conformité {#view-the-static-compliance-violations-report}

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le projet ou le groupe.

Pour afficher le rapport statique sur les violations de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.

Vous pouvez trier le rapport de conformité selon :

- Le niveau de gravité.
- Le type de violation.
- Le titre de la merge request

Vous pouvez filtrer le rapport sur les violations de conformité selon :

- Le projet sur lequel la violation a été trouvée.
- La plage de dates de la violation.
- La branche cible de la violation.

Sélectionnez une ligne pour afficher les détails de la violation de conformité.

### Niveaux de gravité {#severity-levels}

Chaque violation de conformité présente l'un des niveaux de gravité suivants.

<!-- vale gitlab_base.SubstitutionWarning = NO -->

| Icône                                  | Niveau de gravité |
|:--------------------------------------|:---------------|
| {{< icon name="severity-critical" >}} | Critique       |
| {{< icon name="severity-high" >}}     | Élevé           |
| {{< icon name="severity-medium" >}}   | Moyen         |
| {{< icon name="severity-low" >}}      | Faible            |
| {{< icon name="severity-info" >}}     | Info           |

<!-- vale gitlab_base.SubstitutionWarning = YES -->

### Types de violations {#violation-types}

| Violation                         | Niveau de gravité | Catégorie                                      | Description                                                                                                                                                                                                                                            |
|:----------------------------------|:---------------|:----------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Auteur ayant approuvé la merge request     | Élevé           | [Séparation des tâches](#separation-of-duties) | L'auteur de la merge request a approuvé sa propre merge request. Pour plus d'informations, consultez [Empêcher l'approbation par le créateur de la merge request](../../project/merge_requests/approvals/settings.md#prevent-approval-by-merge-request-creator).                     |
| Commiteurs ayant approuvé la merge request | Élevé           | [Séparation des tâches](#separation-of-duties) | Les commiteurs de la merge request ont approuvé la merge request à laquelle ils ont contribué. Pour plus d'informations, consultez [Empêcher les approbations par les utilisateurs qui ajoutent des commits](../../project/merge_requests/approvals/settings.md#prevent-approvals-by-users-who-add-commits). |
| Moins de deux approbations          | Élevé           | [Séparation des tâches](#separation-of-duties) | La merge request a été fusionnée avec moins de deux approbations. Pour plus d'informations, consultez [Règles d'approbation des merge requests](../../project/merge_requests/approvals/rules.md).                                                                                     |

#### Séparation des tâches {#separation-of-duties}

GitLab prend en charge une politique de séparation des tâches entre les utilisateurs qui créent et approuvent des merge requests. Nos critères pour la séparation des tâches sont :

- [Le créateur d'une merge request n'est pas autorisé à approuver sa propre merge request](../../project/merge_requests/approvals/settings.md#prevent-approval-by-merge-request-creator).
- [Un commiteur d'une merge request n'est pas autorisé à approuver une merge request à laquelle il a ajouté des commits](../../project/merge_requests/approvals/settings.md#prevent-approvals-by-users-who-add-commits).
- [Le nombre minimum d'approbations requises pour fusionner une merge request est d'au moins deux](../../project/merge_requests/approvals/rules.md).

### Exporter un rapport des violations de conformité des merge requests dans les projets d'un groupe {#export-a-report-of-merge-request-compliance-violations-on-projects-in-a-group}

Exportez un rapport des violations de conformité des merge requests appartenant à des projets d'un groupe. Rapports :

- N'utilisent pas les filtres du rapport sur les violations.
- Sont tronqués à 15 Mo afin que la pièce jointe à l'e-mail ne soit pas trop volumineuse.

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour exporter un rapport des violations de conformité des merge requests pour les projets d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Dans le coin supérieur droit, sélectionnez **Exporter**.
1. Sélectionnez **Exporter le rapport des violations**.

Un rapport est compilé et envoyé dans votre boîte de réception sous forme de pièce jointe.
