---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: IBM DevOps ClearCase에서 마이그레이션
description: "IBM DevOps ClearCase에서 Git으로 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[IBM DevOps ClearCase](https://www.ibm.com/products/devops-code-clearcase)는 IBM이 개발한 도구 모음이며, Git과 유사한 중앙 집중식 버전 제어 시스템도 포함합니다.

다음 표는 ClearCase와 Git의 주요 차이점을 보여줍니다:

| 기능           | ClearCase                    | Git |
|:------------------|:-----------------------------|:----|
| 리포지토리 모델  | 클라이언트-서버                | 분산 |
| 리비전 ID      | 브랜치 + 번호              | 전역 영숫자 ID |
| 변경 범위   | 파일                         | 디렉터리 트리 스냅샷 |
| 동시성 모델 | 병합                        | 병합 |
| 스토리지 방법    | 델타                       | 전체 콘텐츠 |
| 클라이언트            | CLI, Eclipse, CC Client      | CLI, Eclipse, Git 클라이언트/GUI |
| 서버            | UNIX, Windows 레거시 시스템 | UNIX, macOS |
| 라이선스           | 독점                  | GPL |

## Git으로 마이그레이션 {#migrate-to-git}

IBM DevOps ClearCase에서 Git으로 마이그레이션할 수 있는 도구를 제공하지 않습니다. 마이그레이션에 대한 자세한 내용은 다음 리소스를 참조하세요:

- [Git 및 ClearCase용 Bridge](https://github.com/charleso/git-cc)
- [ClearCase에서 Git로](https://therub.org/2013/07/19/clearcase-to-git/)
- [ClearCase와 Git 이중 동기화](https://therub.org/2013/10/22/dual-syncing-clearcase-and-git/)
- [ClearCase에서 Git으로 이동](https://sateeshkumarb.wordpress.com/2011/01/15/moving-to-git-from-clearcase/)
