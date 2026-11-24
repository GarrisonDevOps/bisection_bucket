---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Migrer depuis Perforce P4
description: "Migrer depuis Perforce P4 vers Git."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Perforce P4](https://www.perforce.com/) propose un ensemble d'outils incluant notamment un système de contrôle de version centralisé et propriétaire similaire à Git.

Les sections suivantes présentent les principales différences entre Perforce P4 et Git :

- La gestion des branches dans Perforce P4 est lourde comparée à la gestion légère des branches dans Git. Lorsque vous créez une branche dans Perforce P4, un enregistrement d'intégration est créé dans sa base de données propriétaire pour chaque fichier de la branche, quel que soit le nombre de fichiers réellement modifiés. Avec Git, un seul SHA fait office de pointeur vers l'état de l'ensemble du dépôt après les modifications, ce qui peut être utile lors de l'adoption de workflows de branches de fonctionnalités.
- Le changement de contexte entre les branches est moins complexe dans Git.
- Avec Git, disposer d'une copie complète du projet et de son historique sur votre ordinateur local signifie que chaque transaction est très rapide. Vous pouvez créer des branches ou fusionner, expérimenter de manière isolée, puis nettoyer avant de partager vos modifications avec d'autres personnes.
- Git simplifie la revue de code, car vous pouvez partager vos modifications sans les fusionner dans la branche par défaut. Perforce P4 nécessitait une fonctionnalité de mise en attente (Shelving) sur le serveur pour permettre aux autres de réviser les modifications avant la fusion.

## Migrer vers Git {#migrate-to-git}

Git inclut une sous-commande (`git p4`) pour effectuer des migrations entre des dépôts Perforce P4 et des dépôts Git.

Pour plus d'informations, consultez :

- [Page de manuel `git-p4`](https://mirrors.edge.kernel.org/pub/software/scm/git/docs/git-p4.html)
- [Documentation `git-p4`](https://git-scm.com/docs/git-p4)
- [Guide de migration Git book](https://git-scm.com/book/en/v2/Git-and-Other-Systems-Migrating-to-Git#_perforce_import)

`git p4` et `git filter-branch` ne sont pas très efficaces pour créer des packfiles Git compacts et optimisés. Il peut être utile de reconditionner correctement votre dépôt avant de l'envoyer pour la première fois vers votre serveur GitLab. Pour plus d'informations, consultez [cette question StackOverflow](https://stackoverflow.com/questions/28720151/git-gc-aggressive-vs-git-repack).
