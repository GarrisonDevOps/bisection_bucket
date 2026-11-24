---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Concurrent Versions System에서 마이그레이션
description: "Concurrent Versions System에서 Git으로 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Concurrent Versions System](https://savannah.nongnu.org/projects/cvs)(CVS)은 [Subversion](https://subversion.apache.org/)과 유사한 중앙화된 버전 제어 시스템입니다.

CVS와 Git의 차이점에 대한 개요는 [Stack Overflow 게시물](https://stackoverflow.com/a/824241/974710)을 참조하세요. 더 자세한 차이점 목록은 Wikipedia 문서 [버전 제어 소프트웨어 비교](https://en.wikipedia.org/wiki/Comparison_of_version_control_software)를 참조하세요.

## Git으로 마이그레이션 {#migrate-to-git}

CVS에서 Git으로 마이그레이션하는 도구를 제공하지 않습니다. 마이그레이션에 대한 자세한 내용은 다음 리소스를 참조하세요:

- [`cvs-fast-export` 도구를 사용하여 마이그레이션](https://gitlab.com/esr/cvs-fast-export)
- [CVS 저장소 가져오기에 관한 Stack Overflow 게시물](https://stackoverflow.com/questions/11362676/how-to-import-and-keep-updated-a-cvs-repository-in-git/11490134#11490134)
- [`git-cvsimport` 도구의 매뉴얼 페이지](https://mirrors.edge.kernel.org/pub/software/scm/git/docs/git-cvsimport.html)
- [`reposurgeon`를 사용하여 마이그레이션](http://www.catb.org/~esr/reposurgeon/repository-editing.html#conversion)
