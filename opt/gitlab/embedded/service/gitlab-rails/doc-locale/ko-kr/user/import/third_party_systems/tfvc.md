---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Team Foundation Version Control에서 마이그레이션
description: "Team Foundation Version Control에서 Git으로 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Team Foundation Version Control](https://learn.microsoft.com/en-us/azure/devops/repos/tfvc/what-is-tfvc?view=azure-devops)(TFVC)은 Git과 유사한 중앙화된 버전 제어 시스템입니다.

TFVC와 Git의 주요 차이점은 다음과 같습니다:

- TFVC는 클라이언트-서버 아키텍처를 사용하는 중앙화된 시스템이지만, Git은 분산형입니다. Git은 전체 리포지토리의 사본으로 작업하기 때문에 더 유연한 워크플로우를 제공합니다. 예를 들어 원격 서버와 통신할 필요 없이 브랜치를 빠르게 전환하거나 병합할 수 있습니다.
- 중앙화된 버전 제어 시스템의 변경 사항은 파일 단위(변경 세트)이지만, Git에서는 커밋된 파일이 전체적으로(스냅샷) 저장됩니다.

자세한 정보는 다음을 참조하세요.

- Microsoft의 [Git과 TFVC 비교](https://learn.microsoft.com/en-us/azure/devops/repos/tfvc/comparison-git-tfvc?view=azure-devops)입니다.
- Wikipedia의 [버전 제어 소프트웨어 비교](https://en.wikipedia.org/wiki/Comparison_of_version_control_software)입니다.

## Git으로 마이그레이션 {#migrate-to-git}

TFVC에서 Git으로 마이그레이션하는 도구는 제공하지 않습니다. 마이그레이션에 대한 정보:

- Microsoft Windows에서 마이그레이션하는 경우 다음을 참조하세요:
  - [`git-tfs`](https://github.com/git-tfs/git-tfs) 도구입니다.
  - [TFS에서 Git으로 마이그레이션 정보](https://github.com/git-tfs/git-tfs/blob/master/doc/usecases/migrate_tfs_to_git.md)입니다.
- Unix 기반 시스템을 사용하는 경우 [TFVC에서 Git으로 마이그레이션 도구](https://github.com/turbo/gtfotfs)를 참조하세요.
