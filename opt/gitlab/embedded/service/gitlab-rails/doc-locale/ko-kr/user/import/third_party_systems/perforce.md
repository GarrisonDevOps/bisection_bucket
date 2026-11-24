---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Perforce P4에서 마이그레이션
description: "Perforce P4에서 Git으로 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Perforce P4](https://www.perforce.com/)는 Git과 유사한 중앙 집중식 독점 버전 제어 시스템을 포함한 도구 세트를 제공합니다.

다음은 Perforce P4와 Git의 주요 차이점입니다:

- Perforce P4 브랜칭은 Git 경량 브랜칭에 비해 무겁습니다. Perforce P4에서 브랜치를 생성하면 실제로 변경된 파일 수에 관계없이 브랜치의 모든 파일에 대해 독점 데이터베이스에 통합 레코드가 생성됩니다. Git에서는 단일 SHA가 변경 후 전체 리포지토리 상태에 대한 포인터로 작동하며, 이는 기능 브랜칭 워크플로를 도입할 때 유용할 수 있습니다.
- Git에서는 브랜치 간 컨텍스트 전환이 덜 복잡합니다.
- Git을 사용하면 로컬 컴퓨터에 프로젝트와 해당 기록의 완전한 복사본이 있다는 것은 모든 트랜잭션이 매우 빠르다는 의미입니다. 브랜칭 또는 병합을 수행하고, 격리된 상태에서 실험한 다음, 변경 사항을 다른 사람과 공유하기 전에 정리할 수 있습니다.
- Git은 기본 브랜치에 병합하지 않고 변경 사항을 공유할 수 있기 때문에 코드 검토를 덜 복잡하게 만듭니다. Perforce P4는 다른 사람들이 병합하기 전에 변경 사항을 검토할 수 있도록 서버의 보관 기능이 필요했습니다.

## Git으로 마이그레이션 {#migrate-to-git}

Git에는 Perforce P4 리포지토리와 Git 리포지토리 간에 이동하기 위한 하위 명령(`git p4`)이 포함됩니다.

자세한 정보는 다음을 참조하세요.

- [`git-p4` 설명서](https://mirrors.edge.kernel.org/pub/software/scm/git/docs/git-p4.html)
- [`git-p4` 설명서](https://git-scm.com/docs/git-p4)
- [Git 도서 마이그레이션 가이드](https://git-scm.com/book/en/v2/Git-and-Other-Systems-Migrating-to-Git#_perforce_import)

`git p4`과 `git filter-branch`는 작고 효율적인 Git packfile을 만드는 데 그다지 좋지 않습니다. GitLab 서버에 처음 전송하기 전에 리포지토리를 제대로 다시 압축할 수 있습니다. 자세한 내용은 [이 StackOverflow 질문](https://stackoverflow.com/questions/28720151/git-gc-aggressive-vs-git-repack)을 참조하세요.
