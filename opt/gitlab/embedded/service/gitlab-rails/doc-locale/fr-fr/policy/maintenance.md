---
stage: GitLab Delivery
group: Release and Deploy
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Politique de release et de maintenance de GitLab
description: "Prise en charge des versions, cadence des releases et politiques de backport."
---

L'équipe Release and Deploy est propriétaire de la politique de maintenance et doit approuver toute mise à jour demandée. Cette approche suit notre modèle DRI et vise à garantir la prévisibilité pour les clients.

GitLab applique des politiques strictes régissant la dénomination des versions et la cadence des releases majeures, mineures et des patchs. Les nouvelles releases sont annoncées dans les [notes de release](https://docs.gitlab.com/releases/).

Notre politique actuelle est la suivante :

- Backport des correctifs de bugs uniquement pour la release stable actuelle à tout moment - voir les [releases de patch](#patch-releases) ci-dessous.
- Backport des correctifs de sécurité vers les deux releases mensuelles précédentes, en plus de la release stable actuelle. Dans certaines circonstances (décrites dans les [releases de patch](#patch-releases) ci-dessous), nous pouvons choisir de traiter une vulnérabilité de sécurité uniquement dans la release stable actuelle ou dans le processus de release mensuel régulier, sans backport.

Dans de rares cas, une exception peut être accordée pour effectuer un backport vers plus des deux dernières releases mensuelles. Pour le processus requis, consultez les [exceptions de politique](#policy-exceptions).

## Gestion des versions {#versioning}

GitLab utilise la [gestion sémantique de version](https://semver.org/) pour ses releases : `(Major).(Minor).(Patch)`.

Par exemple, pour la version GitLab 18.3.2 :

- `18` représente la version majeure. La release majeure était 18.0.0, mais elle est souvent désignée sous le nom 18.0.
- `3` représente la version mineure. La release mineure était 18.3.0, mais elle est souvent désignée sous le nom 18.3.
- `2` représente le numéro de patch.

N'importe quelle partie du numéro de version peut comporter plusieurs chiffres, par exemple 18.3.11.

Le tableau suivant décrit les types de versions et leur cadence de release :

| Type de version | Description | Cadence |
|:-------------|:------------|:--------|
| Majeure        | Pour les changements importants ou lorsque des modifications rétro-incompatibles sont introduites dans l'API publique. | Annuelle. La prochaine release majeure est GitLab 20.0, prévue pour le 20 mai 2027. GitLab [planifie les releases majeures](https://handbook.gitlab.com/handbook/engineering/releases/monthly-releases/) en mai de chaque année, par défaut. |
| Mineure        | Pour l'introduction de nouvelles fonctionnalités rétro-compatibles dans l'API publique, l'introduction d'une fonctionnalité mineure ou le déploiement d'un ensemble de fonctionnalités plus petites. | Mensuelle, prévue le troisième jeudi de chaque mois. |
| Patch        | Pour les correctifs de bugs rétro-compatibles qui corrigent un comportement incorrect. Voir les [releases de patch](#patch-releases). | Deux fois par mois, prévues le mercredi de la semaine précédant et le mercredi de la semaine suivant la release mineure mensuelle. |

<!-- Do not edit the following section without consulting the Technical Writing team -->

<!-- vale gitlab_base.CurrentStatus = NO -->

## Versions maintenues {#maintained-versions}

Les versions de release GitLab suivantes sont actuellement maintenues :

{{< maintained-versions >}}

<!-- vale gitlab_base.CurrentStatus = YES -->

<!-- END -->

> [!note]
> Pour les membres de l'équipe GitLab qui recherchent les versions maintenues pour la prochaine release de patch, consultez le panneau [`Release Versions` panel](https://dashboards.gitlab.net/goto/h228fPEHR?orgId=1) dans la section `Patch Release Information` du tableau de bord Grafana interne `delivery: Release Information`. Lorsque la date de release mensuelle active est antérieure à la date de release de patch active, les versions diffèrent de la liste des versions maintenues ci-dessus.
>
> Les backports de correctifs de bugs sont maintenus pour la version actuelle (première), et les backports de correctifs de sécurité sont maintenus pour toutes les versions.

## Recommandations de mise à niveau {#upgrade-recommendations}

Nous encourageons tout le monde à utiliser la [dernière release stable](https://docs.gitlab.com/releases/) pour s'assurer de pouvoir effectuer une mise à niveau vers l'expérience GitLab la plus sécurisée et la plus riche en fonctionnalités. Pour vous assurer de pouvoir utiliser la release stable la plus récente, nous travaillons activement à maintenir la fiabilité du processus de mise à jour.

Si vous n'êtes pas en mesure de suivre notre cycle de release mensuel, il y a quelques cas que vous devez prendre en compte. Suivez le [guide des chemins de mise à niveau](../update/upgrade_paths.md) pour effectuer une mise à niveau sécurisée entre les versions.

La documentation des changements spécifiques aux versions pour les packages Linux est disponible pour :

- [GitLab 17](../update/versions/gitlab_17_changes.md)
- [GitLab 16](../update/versions/gitlab_16_changes.md)
- [GitLab 15](../update/versions/gitlab_15_changes.md)

Des instructions sont disponibles pour télécharger le package Linux localement et l'[installer manuellement](../update/package/_index.md#upgrade-with-a-downloaded-package).

Un guide étape par étape pour [mettre à niveau le serveur PostgreSQL fourni avec le package Linux est documenté séparément](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server).

## Mise à niveau des versions majeures {#upgrading-major-versions}

Les modifications rétro-incompatibles et les migrations sont réservées aux versions majeures. Pour plus d'informations, consultez [Créer un plan de mise à niveau GitLab](../update/plan_your_upgrade.md).

## Releases de patch {#patch-releases}

Les releases de patch incluent des correctifs de bugs pour la version stable actuellement publiée de GitLab et des correctifs de sécurité pour les deux releases mensuelles précédentes, en plus de la release stable actuelle.

Ces politiques sont en place pour les raisons suivantes :

1. GitLab propose des distributions Community et Enterprise, ce qui double la quantité de travail nécessaire pour tester/publier le logiciel.
1. Le backport vers des releases plus anciennes engendre des coûts élevés en matière de développement, d'assurance qualité et de support.
1. La prise en charge de versions parallèles décourage les mises à niveau incrémentielles qui, au fil du temps, s'accumulent en complexité et créent des difficultés de mise à niveau pour tous les utilisateurs. GitLab dispose d'une équipe dédiée qui s'assure que les mises à niveau incrémentielles (et les installations) sont aussi simples que possible.
1. Le nombre de modifications apportées à l'application GitLab est élevé, ce qui contribue à la complexité du backport vers des releases plus anciennes. Dans plusieurs cas, le backport doit passer par le même processus de révision qu'une nouvelle modification.
1. S'assurer que les tests réussissent sur une release plus ancienne représente un défi considérable dans certains cas et est, par conséquent, très chronophage.

L'intégration de nouvelles fonctionnalités dans une release de patch n'est pas possible, car cela enfreindrait la [gestion sémantique de version](https://semver.org/). Ne pas respecter la [gestion sémantique de version](https://semver.org/) a les conséquences suivantes pour les utilisateurs qui doivent se conformer à diverses exigences internes (par exemple, conformité organisationnelle, vérification des nouvelles fonctionnalités, etc.) :

1. Impossibilité d'effectuer rapidement une mise à niveau pour tirer parti des correctifs de bugs inclus dans les versions de patch.
1. Impossibilité d'effectuer rapidement une mise à niveau pour tirer parti des correctifs de sécurité inclus dans les versions de patch.
1. Des exigences impliquant des tests approfondis non seulement pour la release stable de GitLab, mais aussi pour chaque version de patch.

Pour les problèmes de sécurité très graves, il existe un [précédent](https://about.gitlab.com/releases/2016/05/02/cve-2016-4340-patches/) consistant à effectuer un backport des correctifs de sécurité vers des versions encore plus anciennes de GitLab. Pour le processus requis, consultez les [exceptions de politique](#policy-exceptions).

Dans certaines circonstances, nous pouvons choisir de traiter une vulnérabilité en utilisant le processus de release mensuel régulier, en mettant à jour uniquement les releases actives et stables actuelles, sans backport. Les facteurs influençant cette décision incluent la très faible probabilité d'exploitation, le faible impact de la vulnérabilité, la complexité des correctifs de sécurité et le risque éventuel pour la stabilité. Nous traitons toujours les problèmes de sécurité élevés et critiques par le biais d'une release de patch.

## Exceptions de politique {#policy-exceptions}

Dans des circonstances exceptionnelles, des dérogations à cette politique de maintenance peuvent s'avérer nécessaires. Cela inclut les demandes de backport de correctifs vers des releases plus anciennes que celles couvertes par la politique standard, ainsi que les dérogations aux [principes de release](https://handbook.gitlab.com/handbook/engineering/releases/#what-each-release-type-contains). Les demandes de gravité 3 et inférieure sont automatiquement rejetées.

Pour demander une exception de politique, suivez les directives du [processus d'exception](https://handbook.gitlab.com/handbook/engineering/releases/#exception-process).

Le [processus d'exception de release](https://handbook.gitlab.com/handbook/engineering/releases/#exception-process) décrit les directives pour demander une exception de politique. Les exceptions sont accordées à la discrétion des [Release Managers](https://about.gitlab.com/community/release-managers/) en tant que propriétaires de la politique, sous réserve des [engagements SLO](https://handbook.gitlab.com/handbook/engineering/releases/patch-releases/#slo-commitments).

## Plus d'informations {#more-information}

Vous pouvez également consulter :

- [Documentation sur les releases](https://gitlab.com/gitlab-org/release/docs) décrivant les procédures de release
- Directives relatives aux dépréciations dans la documentation de développement.
- [Politique de divulgation responsable](https://about.gitlab.com/security/disclosure/)
