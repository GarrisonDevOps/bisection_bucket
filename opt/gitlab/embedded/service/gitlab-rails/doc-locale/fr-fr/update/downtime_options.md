---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Considérer les options d'indisponibilité lors d'une mise à niveau"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

Les options d'indisponibilité lors d'une mise à niveau dépendent du type de votre instance :

- Instance à nœud unique : vous devez effectuer la mise à niveau avec une période d'indisponibilité. Les utilisateurs voient un message **Deploy in progress** ou une erreur `502`.
- Instance multi-nœuds : choisissez entre une mise à niveau avec ou sans indisponibilité.

Pour effectuer une mise à niveau sur plusieurs versions mineures (par exemple, de la version 14.6 à la version 14.9), vous devez mettre votre instance GitLab hors ligne et effectuer la mise à niveau avec une période d'indisponibilité.

## Mises à niveau avec indisponibilité {#upgrades-with-downtime}

Avant de commencer, consultez les notes de mise à niveau spécifiques à votre version pour votre [chemin de mise à niveau](upgrade_paths.md) :

- [Notes de mise à niveau GitLab 17](versions/gitlab_17_changes.md)
- [Notes de mise à niveau GitLab 16](versions/gitlab_16_changes.md)
- [Notes de mise à niveau GitLab 15](versions/gitlab_15_changes.md)

Pour les instances à nœud unique, consultez [la mise à niveau des instances de package Linux](package/_index.md). Pour les instances multi-nœuds, consultez [la mise à niveau d'une instance multi-nœuds avec indisponibilité](with_downtime.md).

## Mises à niveau sans interruption {#zero-downtime-upgrades}

Les mises à niveau sans interruption vous permettent de mettre à niveau un environnement GitLab en production sans le mettre hors ligne.

Pour une mise à niveau sans interruption, mettez à niveau les nœuds GitLab dans un ordre spécifique. Utilisez l'équilibrage de charge, les systèmes haute disponibilité (HA) et les rechargements progressifs pour minimiser les perturbations.

La documentation couvre uniquement les composants principaux de GitLab. Pour les mises à niveau ou la gestion de services tiers tels qu'AWS RDS, consultez leur documentation.

Pour effectuer une mise à niveau sans interruption, consultez la documentation correspondant à votre méthode d'installation : [Charts Helm](https://docs.gitlab.com/charts/installation/upgrade/), [GitLab Operator](https://docs.gitlab.com/operator/gitlab_upgrades/) ou [instances multi-nœuds](zero_downtime.md).
