---
stage: Security Risk Management
group: Security Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: "Résultats de l'analyse de sécurité"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/490334) dans GitLab 17.9 [avec le feature flag](../../../administration/feature_flags/_index.md) `dependency_scanning_for_pipelines_with_cyclonedx_reports`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com et GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/issues/490332) dans GitLab 17.9.
- Feature flag `dependency_scanning_for_pipelines_with_cyclonedx_reports` supprimé dans la version 17.10.

{{< /history >}}

Consultez et agissez sur les résultats de l'analyse de sécurité de pipeline dans GitLab. Les scanners de sécurité s'exécutent dans un pipeline et génèrent des rapports de sécurité. Le contenu de ces rapports est traité et présenté dans GitLab.

L'analyse de sécurité doit être configurée pour votre projet afin de générer des résultats. Pour plus d'informations sur la configuration des scanners de sécurité, consultez [Configuration de la sécurité](security_configuration.md).

Terminologie clé pour comprendre les résultats de l'analyse de sécurité :

Finding : un finding est une vulnérabilité potentielle identifiée dans une branche de développement. Un finding devient une vulnérabilité lorsque la branche est fusionnée dans la branche par défaut. : les findings expirent soit lorsque l'artefact de job CI/CD associé expire, soit après une période définie suivant la création du pipeline, même si les artefacts de job associés sont verrouillés. La période est de 30 jours sur GitLab.com. Sur GitLab Self-Managed et GitLab Dedicated, la valeur par défaut est de 90 jours. Un administrateur peut [modifier la période de rétention](../../../administration/settings/security_and_compliance.md#security-scan-retention-period) à une valeur comprise entre 7 et 90 jours.

Vulnérabilité : une vulnérabilité est une faiblesse de sécurité logicielle identifiée dans la branche par défaut. : les enregistrements de vulnérabilités persistent jusqu'à ce qu'ils soient [archivés](../vulnerability_archival/_index.md), même si la vulnérabilité n'est plus détectée dans la branche par défaut.

Les vulnérabilités identifiées dans la branche par défaut sont répertoriées dans le [rapport des vulnérabilités](../vulnerability_report/_index.md).

## Artefacts de rapport de sécurité {#security-report-artifacts}

Les scanners de sécurité s'exécutent dans les pipelines de branche et, si activés, dans les pipelines de merge request. Chaque scanner de sécurité génère un artefact de rapport de sécurité contenant les détails de tous les findings ou vulnérabilités détectés par ce scanner de sécurité spécifique.

Les rapports de sécurité des [pipelines enfants](../../../ci/pipelines/downstream_pipelines.md#view-child-pipeline-reports-in-merge-requests) sont inclus dans les rapports de sécurité de pipeline et les rapports de merge request.

Dans une branche de développement (non par défaut), les findings incluent toutes les vulnérabilités présentes dans la branche cible au moment de la création de la branche de développement.

les findings expirent soit lorsque l'artefact de job CI/CD associé expire, soit après une période définie suivant la création du pipeline, même si les artefacts de job associés sont verrouillés. La période est de 30 jours sur GitLab.com. Sur GitLab Self-Managed et GitLab Dedicated, la valeur par défaut est de 90 jours, et un administrateur peut modifier la période de rétention à une valeur comprise entre 7 et 90 jours. Les findings expirés ne sont pas affichés dans l'onglet **Sécurité** du pipeline. Pour les reproduire, relancez le pipeline.

### Télécharger un rapport de sécurité {#download-a-security-report}

{{< details >}}

- Édition : GitLab Ultimate

{{< /details >}}

Vous pouvez télécharger un rapport de sécurité, par exemple pour l'analyser en dehors de GitLab ou à des fins d'archivage. Un rapport de sécurité est un fichier JSON.

Prérequis :

- Disposer du rôle Responsable sécurité, Développeur, Chargé de maintenance ou Propriétaire pour le projet.

Pour télécharger un rapport de sécurité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**.
1. Sélectionnez le pipeline.
1. Sélectionnez l'onglet **Sécurisation**.
1. Sélectionnez **Télécharger les résultats**, puis le rapport de sécurité souhaité.

Le rapport de sécurité sélectionné est téléchargé sur votre appareil.

![Liste des rapports de sécurité](img/security_report_v18_1.png)

## Rapport de sécurité de pipeline {#pipeline-security-report}

{{< details >}}

- Édition : GitLab Ultimate

{{< /details >}}

Le rapport de sécurité de pipeline contient les détails de tous les findings ou vulnérabilités détectés par cette exécution de pipeline. Les résultats reflètent l'état de la branche au moment du commit sur lequel le pipeline s'est exécuté. Ainsi, différents pipelines sur la même branche peuvent afficher des résultats différents. Pour une exécution de pipeline sur la branche par défaut, toutes les vulnérabilités du rapport de sécurité de pipeline figurent également dans le rapport des vulnérabilités.

![Liste des findings détectés par une exécution de pipeline](img/pipeline_security_report_v18_1.png)

### Consulter le rapport de sécurité de pipeline {#view-pipeline-security-report}

Consultez le rapport de sécurité de pipeline pour voir les détails de tous les findings ou vulnérabilités détectés par une exécution de pipeline.

Prérequis :

- Disposer du rôle Responsable sécurité, Développeur, Chargé de maintenance ou Propriétaire pour le projet.

Pour consulter un rapport de sécurité de pipeline :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**.
1. Sélectionnez le dernier pipeline.

Pour voir les détails d'un finding ou d'une vulnérabilité, sélectionnez sa description.

### Créer un ticket {#create-an-issue}

Créez un ticket pour suivre, documenter et gérer le travail de remédiation d'un finding ou d'une vulnérabilité.

Prérequis :

- Disposer du rôle Responsable sécurité, Développeur, Chargé de maintenance ou Propriétaire pour le projet.

Pour créer un ticket :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**.
1. Sélectionnez le pipeline.
1. Sélectionnez l'onglet **Sécurisation**.
1. Sélectionnez la description d'un finding.
1. Sélectionnez **Créer un ticket**.

Un ticket est créé dans le projet, avec la description copiée depuis la description du finding ou de la vulnérabilité.

### Modifier le statut {#change-status}

Vous pouvez modifier le statut d'un finding ou d'une vulnérabilité dans l'onglet de sécurité du pipeline. Toutes les modifications apportées à un finding persistent lorsque la branche est fusionnée dans la branche par défaut.

Prérequis :

- Le rôle Maintainer pour le projet ou l'autorisation personnalisée `admin_vulnerability`.

Pour modifier le statut des findings ou des vulnérabilités :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**.
1. Sélectionnez le dernier pipeline.
1. Sélectionnez l'onglet **Sécurisation**.
1. Dans le rapport de findings :

     1. Sélectionnez les findings ou les vulnérabilités que vous souhaitez modifier.

        - Pour sélectionner des findings ou des vulnérabilités individuels, cochez la case à côté de chacun d'eux.
        - Pour sélectionner tous les findings ou toutes les vulnérabilités de la page, cochez la case dans l'en-tête du tableau.

     1. Dans la liste déroulante **Sélectionner une action**, sélectionnez **Rejetée** ou **Needs Triage**.
     1. Sélectionnez **Modifier le statut**.

### Télécharger un rapport de sécurité {#download-a-security-report-1}

{{< details >}}

- Édition : GitLab Ultimate

{{< /details >}}

Vous pouvez télécharger un rapport de sécurité, par exemple pour l'analyser en dehors de GitLab ou à des fins d'archivage. Un rapport de sécurité est un fichier JSON.

Prérequis :

- Disposer du rôle Responsable sécurité, Développeur, Chargé de maintenance ou Propriétaire pour le projet.

Pour télécharger un rapport de sécurité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Compilation** > **Pipelines**.
1. Sélectionnez le pipeline.
1. Sélectionnez l'onglet **Sécurisation**.
1. Sélectionnez **Télécharger les résultats**, puis le rapport de sécurité souhaité.

Le rapport de sécurité sélectionné est téléchargé sur votre appareil.

![Liste des rapports de sécurité](img/security_report_v18_1.png)

## Rapports de merge request {#merge-request-reports}

Pour les résultats d'analyse de sécurité dans une merge request, consultez les [rapports de merge request](../../project/merge_requests/reports.md).

## Dépannage {#troubleshooting}

Lorsque vous travaillez avec l'analyse de sécurité, vous pouvez rencontrer les problèmes suivants.

### Erreurs d'analyse de rapport et d'ingestion de scan {#report-parsing-and-scan-ingestion-errors}

> [!note]
> Ces étapes sont destinées à être utilisées par le Support GitLab pour reproduire ce type d'erreurs.

Certaines analyses de sécurité peuvent générer des erreurs dans l'onglet **Sécurité** du pipeline, liées à l'analyse du rapport ou à l'ingestion du scan. S'il n'est pas possible d'obtenir une copie du projet auprès de l'utilisateur, vous pouvez reproduire l'erreur en utilisant le rapport généré par l'analyse.

Pour recréer l'erreur :

1. Obtenez une copie du rapport auprès de l'utilisateur. Dans cet exemple, `gl-sast-report.json`.
1. Créez un projet.
1. Committez le rapport dans le dépôt.
1. Ajoutez votre fichier `.gitlab-ci.yml` et incluez le rapport comme artefact dans un job.

   Par exemple, pour reproduire une erreur causée par un job SAST :

   ```yaml
   sample-job:
     script:
       - echo "Testing report"
     artifacts:
       reports:
         sast: gl-sast-report.json
   ```

1. Une fois le pipeline terminé, vérifiez le contenu de l'onglet **Sécurité** du pipeline pour détecter les erreurs.

Vous pouvez remplacer `sast: gl-sast-report.json` par le type [`artifacts:reports`](../../../ci/yaml/_index.md#artifactsreports) correspondant et le nom de fichier JSON correct en fonction de l'analyse qui a généré le rapport.
