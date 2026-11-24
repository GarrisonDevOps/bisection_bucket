---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Les merge requests affichent les résultats des pipelines CI/CD et des tests de fusionnabilité dans une zone de rapports.
title: Widgets de merge request
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

La page de vue d'ensemble d'une merge request affiche les mises à jour de statut provenant des services qui effectuent des actions sur votre merge request. Tous les niveaux d'abonnement affichent une zone de widgets, mais le contenu de cette zone dépend de votre niveau d'abonnement et des services que vous configurez pour votre projet.

## Informations sur le pipeline {#pipeline-information}

Si vous avez configuré [GitLab CI/CD](../../../ci/_index.md) dans votre projet, une [merge request](_index.md) affiche les informations du pipeline dans la zone des widgets de l'onglet **Vue d'ensemble** :

- Les pipelines pré-fusion et post-fusion, ainsi que les informations sur l'environnement, le cas échéant.
- Les déploiements en cours.

Si une application est déployée avec succès dans un [environnement](../../../ci/environments/_index.md), l'environnement déployé et le lien vers l'[environnement éphémère](../../../ci/review_apps/_index.md) sont tous deux affichés.

Lorsque le pipeline échoue dans une merge request mais que la fusion reste possible, GitLab affiche **Fusionner** en rouge.

## Statut du pipeline post-fusion {#post-merge-pipeline-status}

Lorsque vous fusionnez une merge request, vous pouvez consulter le statut du pipeline post-fusion de la branche dans laquelle la merge request a été fusionnée. Par exemple, lorsqu'une merge request est fusionnée dans la [branche par défaut](../repository/branches/default.md), puis déclenche un déploiement vers l'environnement de staging.

GitLab affiche les déploiements en cours ainsi que l'état (en cours de déploiement ou déployé) pour les environnements. S'il s'agit du premier déploiement de la branche, le lien renvoie une erreur `404` jusqu'à la fin du déploiement. Pendant le déploiement, GitLab désactive le bouton d'arrêt. Si le pipeline échoue lors du déploiement, GitLab masque les informations de déploiement.

![Widgets de merge request affichant le statut du pipeline post-fusion](img/post_merge_pipeline_v16_0.png)

Pour plus d'informations, [consultez la documentation sur les pipelines](../../../ci/pipelines/_index.md).

## Configurer la fusion automatique {#set-auto-merge}

Configurez une merge request prête à être fusionnée pour qu'elle [fusionne automatiquement lorsque le pipeline CI réussit](auto_merge.md).

## Aperçu en direct avec les environnements éphémères {#live-preview-with-review-apps}

Configurez des [environnements éphémères](../../../ci/review_apps/_index.md) pour votre projet afin de prévisualiser les modifications soumises à une branche de fonctionnalité via une merge request, branche par branche. Vous n'avez pas besoin d'extraire la branche, de l'installer ni d'effectuer une prévisualisation en local. Toutes vos modifications sont disponibles en prévisualisation pour toute personne disposant du lien vers les environnements éphémères.

Avec les [mappages de routes](../../../ci/review_apps/_index.md#route-maps) GitLab configurés, le widget de merge request vous redirige directement vers les pages modifiées, facilitant et accélérant la prévisualisation des modifications proposées.

Pour plus d'informations, consultez [les environnements éphémères](../../../ci/review_apps/_index.md).

## Conformité des licences {#license-compliance}

Pour les informations de conformité des licences dans les merge requests, consultez [les rapports de merge request](reports.md).

## Politiques de sécurité {#security-policies}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour empêcher les développeurs de fusionner des vulnérabilités et des licences non prises en charge, ou pour imposer des approbations obligatoires dans les merge requests, configurez des [politiques de sécurité](../../application_security/policies/merge_request_approval_policies.md). Vous pouvez configurer des politiques de sécurité pour un projet, un groupe ou une instance. En option, vous pouvez définir les politiques de sécurité en mode avertissement afin de sensibiliser aux résultats sans empêcher les développeurs de fusionner.

## Vérifications de statut externes {#external-status-checks}

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si vous avez configuré des [vérifications de statut externes](status_checks.md), vous pouvez consulter le statut de ces vérifications dans les merge requests [dans un widget spécifique](status_checks.md#status-checks-widget).

## Analyse de sécurité des applications {#application-security-scanning}

Pour les résultats de l'analyse de sécurité des applications dans les merge requests, consultez [les rapports de merge request](reports.md).
