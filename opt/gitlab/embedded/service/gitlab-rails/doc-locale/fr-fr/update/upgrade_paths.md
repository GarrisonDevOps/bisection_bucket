---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Planifier votre chemin de mise à niveau
description: Instructions pour la dernière version.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Un chemin de mise à niveau comprend les étapes permettant de passer de votre version actuelle de GitLab à la version de GitLab vers laquelle vous souhaitez effectuer la mise à niveau. Pour déterminer votre chemin de mise à niveau :

1. Notez à quel endroit du chemin de mise à niveau se situe votre version actuelle, y compris les arrêts de mise à niveau obligatoires.
1. Consultez les [notes de mise à niveau de GitLab](versions/_index.md).

Même lorsque cela n'est pas explicitement spécifié, mettez à niveau GitLab vers la dernière version de patch disponible de la release `major`.`minor` plutôt que vers la première version de patch. Par exemple, `16.8.7` au lieu de `16.8.0`.

Certaines versions `major`.`minor` sont des arrêts obligatoires pour certains ou tous les environnements, car elles contiennent des correctifs pour des problèmes liés au processus de mise à niveau.

## Arrêts de mise à niveau obligatoires {#required-upgrade-stops}

Les chemins de mise à niveau incluent des arrêts de mise à niveau obligatoires, qui sont des versions de GitLab vers lesquelles vous devez effectuer la mise à niveau avant de passer aux versions ultérieures. Lors du parcours d'un chemin de mise à niveau :

1. Effectuez la mise à niveau vers l'arrêt de mise à niveau obligatoire suivant votre version actuelle.
1. Attendez que les migrations en arrière-plan de la mise à niveau se terminent.
1. Effectuez la mise à niveau vers le prochain arrêt de mise à niveau obligatoire.

Dans GitLab 17.5 et les versions ultérieures, afin de fournir un calendrier de mise à niveau prévisible pour les administrateurs d'instance, les arrêts de mise à niveau obligatoires se produisent aux versions `x.2.z`, `x.5.z`, `x.8.z` et `x.11.z`.

Pour vérifier les versions de patch disponibles pour une version mineure spécifique, vous pouvez rechercher la version mineure dans le [dépôt de paquets GitLab](https://packages.gitlab.com/ui/browse/gitlab).

Si vous effectuez la mise à niveau d'une instance GitLab Helm chart, consultez la [liste des correspondances GitLab Helm chart](https://docs.gitlab.com/charts/installation/version_mappings/#previous-chart-versions).

### Arrêts de mise à niveau obligatoires pour GitLab 19 {#required-gitlab-19-upgrade-stops}

> [!note]
> Certaines de ces versions peuvent ne pas encore être disponibles. Pour vérifier les versions disponibles, consultez les [notes de release de GitLab 19](../releases/19/_index.md).

Les arrêts de mise à niveau obligatoires se produisent aux versions :

- `19.2`
- `19.5`
- `19.8`
- `19.11`

Vous devez effectuer la mise à niveau vers ces versions de GitLab 19 avant de passer aux versions ultérieures. Pour chaque version vers laquelle vous effectuez la mise à niveau, consultez les [notes de mise à niveau pour GitLab 19](versions/gitlab_19_changes.md). Si une version n'est pas mentionnée dans les notes de mise à niveau, il n'y a rien de spécifique à connaître concernant cette version.

Trouvez les versions de patch dans le dépôt de paquets GitLab. Par exemple, pour rechercher la dernière version GitLab 19.2 Enterprise Edition pour Ubuntu 24.04 :

1. Accédez à <https://packages.gitlab.com/ui/browse/gitlab/gitlab-ee/ubuntu/noble/pool/main/g/gitlab-ee>.
1. Saisissez `19.2` comme terme de recherche.

### Arrêts de mise à niveau obligatoires pour GitLab 18 {#required-gitlab-18-upgrade-stops}

Les arrêts de mise à niveau obligatoires se produisent aux versions `18.2`, `18.5`, `18.8` et `18.11`.

Vous devez effectuer la mise à niveau vers ces versions de GitLab 18 avant de passer aux versions ultérieures. Pour chaque version vers laquelle vous effectuez la mise à niveau, consultez les [notes de mise à niveau pour GitLab 18](versions/gitlab_18_changes.md). Si une version n'est pas mentionnée dans les notes de mise à niveau, il n'y a rien de spécifique à connaître concernant cette version.

Trouvez les versions de patch dans le dépôt de paquets GitLab. Par exemple, pour rechercher la dernière version GitLab 18.2 Enterprise Edition pour Ubuntu 24.04 :

1. Accédez à <https://packages.gitlab.com/ui/browse/gitlab/gitlab-ee/ubuntu/noble/pool/main/g/gitlab-ee>.
1. Saisissez `18.2` comme terme de recherche.

### Arrêts de mise à niveau obligatoires pour GitLab 17 {#required-gitlab-17-upgrade-stops}

Vous devez effectuer la mise à niveau vers ces versions de GitLab 17 avant de passer aux versions ultérieures.

| Version requise | Remarques |
|:-----------------|:------|
| 17.11.7          | Effectuez la mise à niveau vers la dernière version de patch GitLab 17.11. Consultez les [notes de mise à niveau pour GitLab 17.11.0](versions/gitlab_17_changes.md#upgrades-to-17110). |
| 17.8.7           | Effectuez la mise à niveau vers la dernière version de patch GitLab 17.8. Consultez les [notes de mise à niveau pour GitLab 17.8.0](versions/gitlab_17_changes.md#upgrades-to-1780). |
| 17.5.5           | Effectuez la mise à niveau vers la dernière version de patch GitLab 17.5. Consultez les [notes de mise à niveau pour GitLab 17.5.0](versions/gitlab_17_changes.md#upgrades-to-1750). |
| 17.3.7           | Effectuez la mise à niveau vers la dernière release de GitLab 17.3. Consultez les [notes de mise à niveau pour GitLab 17.3.0](versions/gitlab_17_changes.md#upgrades-to-1730). |
| 17.1.8           | Requis uniquement pour les instances avec [des tables `ci_pipeline_messages` volumineuses](versions/gitlab_17_changes.md#long-running-pipeline-messages-data-change). Consultez les [notes de mise à niveau pour GitLab 17.1.0](versions/gitlab_17_changes.md#upgrades-to-1710).|

### Arrêts de mise à niveau obligatoires pour GitLab 16 {#required-gitlab-16-upgrade-stops}

Vous devez effectuer la mise à niveau vers ces versions de GitLab 16 avant de passer aux versions ultérieures.

| Version requise | Remarques |
|:-----------------|:------|
| 16.11.10         | Consultez les [notes de mise à niveau pour GitLab 16.11.0](versions/gitlab_16_changes.md#16110). |
| 16.7.10          | Consultez les [notes de mise à niveau pour GitLab 16.8.0](versions/gitlab_16_changes.md#1670) et les versions ultérieures de GitLab 16.7. |
| 16.3.9           | Consultez les [notes de mise à niveau pour GitLab 16.3.0](versions/gitlab_16_changes.md#1630) et les versions ultérieures de GitLab 16.3. |
| 16.2.11          | Requis uniquement pour les instances GitLab avec [un historique de variables de pipeline volumineux](versions/gitlab_16_changes.md#1630). Consultez les [notes de mise à niveau pour GitLab 16.2.0](versions/gitlab_16_changes.md#1620). |
| 16.1.8           | Requis uniquement pour les instances GitLab [ayant des paquets NPM dans leur registre de paquets](versions/gitlab_16_changes.md#1610). Consultez les [notes de mise à niveau pour GitLab 16.1.0](versions/gitlab_16_changes.md#1610). |
| 16.0.10          | Requis uniquement pour les instances GitLab avec [un grand nombre d'utilisateurs](versions/gitlab_16_changes.md#long-running-user-type-data-change) ou [un historique de variables de pipeline volumineux](versions/gitlab_16_changes.md#1610). Consultez les [notes de mise à niveau pour GitLab 16.0.0](versions/gitlab_16_changes.md#1600) et les versions ultérieures de GitLab 16.0. |

### Arrêts de mise à niveau obligatoires pour GitLab 15 {#required-gitlab-15-upgrade-stops}

Vous devez effectuer la mise à niveau vers ces versions de GitLab 15 avant de passer aux versions ultérieures.

| Version requise | Remarques |
|:-----------------|:------|
| 15.11.13         | Consultez les [notes de mise à niveau pour GitLab 15.11.0](versions/gitlab_15_changes.md#15110) et les versions ultérieures de GitLab 15.11. |
| 15.4.6           | Consultez les [notes de mise à niveau pour GitLab 15.4.0](versions/gitlab_15_changes.md#1540) et les versions ultérieures de GitLab 15.4. |
| 15.1.6           | Requis uniquement pour les instances GitLab avec plusieurs nœuds web. Consultez les [notes de mise à niveau pour GitLab 15.1.0](versions/gitlab_15_changes.md#1510). |
| 15.0.5           | Consultez les [notes de mise à niveau pour GitLab 15.0](versions/gitlab_15_changes.md#1500). |

## Outil Upgrade Path {#upgrade-path-tool}

Pour calculer rapidement les arrêts de mise à niveau requis en fonction de votre version GitLab actuelle et de la version cible souhaitée, consultez l'[outil Upgrade Path](https://gitlab-com.gitlab.io/support/toolbox/upgrade-path/). Cet outil est maintenu par l'équipe Support de GitLab.

Pour partager vos commentaires et contribuer à l'amélioration de l'outil, créez un ticket ou une merge request dans le [projet `upgrade-path`](https://gitlab.com/gitlab-com/support/toolbox/upgrade-path).

## Versions antérieures de GitLab {#earlier-gitlab-versions}

Pour obtenir des informations sur la mise à niveau vers des versions antérieures de GitLab, consultez les [archives de la documentation](https://archives.docs.gitlab.com). Les versions de la documentation présentes dans les archives contiennent des informations spécifiques aux versions antérieures de GitLab.
