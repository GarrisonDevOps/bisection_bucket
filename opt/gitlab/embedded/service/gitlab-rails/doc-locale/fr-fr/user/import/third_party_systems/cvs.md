---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Migrer depuis Concurrent Versions System
description: "Migrer depuis Concurrent Versions System vers Git."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Concurrent Versions System](https://savannah.nongnu.org/projects/cvs) (CVS) est un système de contrôle de version centralisé similaire à [Subversion](https://subversion.apache.org/).

Pour avoir une vue d'ensemble des différences entre CVS et Git, consultez ce [post Stack Overflow](https://stackoverflow.com/a/824241/974710). Pour une liste plus complète des différences, consultez l'article Wikipédia [comparant les différents logiciels de contrôle de version](https://en.wikipedia.org/wiki/Comparison_of_version_control_software).

## Migrer vers Git {#migrate-to-git}

Nous ne proposons pas d'outil pour migrer de CVS vers Git. Pour plus d'informations sur la migration, consultez ces ressources :

- [Migrer à l'aide de l'outil `cvs-fast-export`](https://gitlab.com/esr/cvs-fast-export)
- [Post Stack Overflow sur l'importation de dépôts CVS](https://stackoverflow.com/questions/11362676/how-to-import-and-keep-updated-a-cvs-repository-in-git/11490134#11490134)
- [Page man de l'outil `git-cvsimport`](https://mirrors.edge.kernel.org/pub/software/scm/git/docs/git-cvsimport.html)
- [Migrer à l'aide de `reposurgeon`](http://www.catb.org/~esr/reposurgeon/repository-editing.html#conversion)
