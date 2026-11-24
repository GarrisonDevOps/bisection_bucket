---
stage: Tenant Scale
group: Gitaly
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Résolution des problèmes de performance des monodépôts
---

Consultez ces suggestions pour résoudre les problèmes de performance liés aux monodépôts.

## Lenteur lors de `git clone` ou de `git fetch` {#slowness-during-git-clone-or-git-fetch}

Il existe quelques causes principales de lenteur lors des clones et des fetches.

### Utilisation élevée du CPU {#high-cpu-utilization}

Si l'utilisation du CPU sur vos nœuds Gitaly est élevée, vous pouvez également vérifier la part de CPU consommée par les clones en [filtrant sur certaines valeurs](observability.md#cpu-and-memory).

En particulier, le champ `command.cpu_time_ms` peut indiquer la part de CPU consommée par les clones et les fetches.

Dans la plupart des cas, la majeure partie de la charge serveur est générée par les processus `git-pack-objects`, qui sont initiés lors des clones et des fetches. Les monodépôts sont souvent très sollicités et les systèmes CI/CD envoient de nombreuses commandes de clone et de fetch au serveur.

Une utilisation élevée du CPU est une cause fréquente de lenteur des performances. Les causes suivantes, non mutuellement exclusives, sont possibles :

- [Trop de clones pour que Gitaly puisse les gérer](#cause-too-many-large-clones).
- [Mauvaise distribution des lectures sur Gitaly Cluster (Praefect)](#cause-poor-read-distribution).

#### Cause : trop de clones volumineux {#cause-too-many-large-clones}

Il est possible que vous ayez trop de clones volumineux pour que Gitaly puisse les gérer. Gitaly peut avoir du mal à suivre en raison d'un certain nombre de facteurs :

- La taille d'un dépôt.
- Le volume de clones et de fetches.
- Manque de capacité CPU.

Pour aider Gitaly à traiter de nombreux clones volumineux, vous devrez peut-être réduire la charge sur les serveurs Gitaly grâce à certaines stratégies d'optimisation, telles que :

- Activez le [pack-objects-cache](../../../../administration/gitaly/configure_gitaly.md#pack-objects-cache) pour réduire le travail que `git-pack-objects` doit effectuer.
- Modifiez la [stratégie Git](_index.md#use-git-fetch-in-cicd-operations) dans les paramètres CI/CD en remplaçant `clone` par `fetch` ou `none`.
- [Arrêtez de récupérer les tags](_index.md#change-git-fetch-behavior-with-flags), sauf si vos tests en ont besoin.
- [Utilisez des clones superficiels](_index.md#use-shallow-clones-and-filters-in-cicd-processes) chaque fois que possible.

L'autre option consiste à augmenter la capacité CPU sur les serveurs Gitaly.

#### Cause : mauvaise distribution des lectures {#cause-poor-read-distribution}

Il est possible que vous ayez une mauvaise distribution des lectures sur Gitaly Cluster (Praefect).

Pour observer si la majeure partie du trafic en lecture est dirigée vers le nœud Gitaly principal au lieu d'être distribuée sur l'ensemble du cluster, utilisez la [métrique Prometheus de distribution des lectures](observability.md#read-distribution).

Si les nœuds Gitaly secondaires ne reçoivent pas beaucoup de trafic, il est possible que ces nœuds secondaires soient perpétuellement désynchronisés. Ce problème est aggravé dans le cas d'un monodépôt.

Les monodépôts sont souvent à la fois volumineux et très sollicités. Cela entraîne deux effets. Premièrement, les monodépôts font l'objet de nombreux pushs et de nombreux jobs CI s'y exécutent. Il peut arriver que des opérations d'écriture, telles que la suppression d'une branche, échouent lors d'un appel proxy vers les nœuds secondaires. Cela déclenche un job de réplication dans Gitaly Cluster (Praefect) afin que le nœud secondaire puisse éventuellement se synchroniser.

Le job de réplication est essentiellement un `git fetch` depuis le nœud secondaire vers le nœud principal, et comme les monodépôts sont souvent très volumineux, ce fetch peut prendre beaucoup de temps.

Si le prochain appel échoue avant que le job de réplication précédent ne se termine, et que cela se répète, vous pouvez vous retrouver dans un état où votre monodépôt est constamment en retard sur ses nœuds secondaires. Cela entraîne la redirection de tout le trafic vers le nœud principal.

L'une des raisons de ces échecs d'écritures mandatées est un problème connu avec le fichier Git `$GIT_DIR/packed-refs`. Le fichier doit être verrouillé pour supprimer une entrée, ce qui peut entraîner une condition de concurrence provoquant l'échec d'une suppression lorsque des suppressions simultanées se produisent.

Les ingénieurs de GitLab ont développé des mesures d'atténuation pour tenter de regrouper les suppressions de références en lots.

Activez les [feature flags](../../../../administration/feature_flags/_index.md) suivants pour permettre à GitLab de regrouper les suppressions de références en lots. Ces feature flags ne nécessitent pas d'interruption de service pour être activés.

- `merge_request_cleanup_ref_worker_async`
- `pipeline_cleanup_ref_worker_async`
- `pipeline_delete_gitaly_refs_in_batches`
- `merge_request_delete_gitaly_refs_in_batches`

L'[epic 4220](https://gitlab.com/groups/gitlab-org/-/epics/4220) propose d'ajouter la prise en charge de RefTable dans GitLab, ce qui est considéré comme une solution à long terme.
