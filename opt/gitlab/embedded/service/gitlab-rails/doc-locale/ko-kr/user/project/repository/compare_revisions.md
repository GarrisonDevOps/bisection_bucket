---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "리포지토리에서 리비전 간의 차이를 보기 위해 브랜치, 태그, 커밋을 비교합니다."
title: 버전 비교
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

**리비전 비교**를 사용하여 리비전 간 변경된 커밋 및 파일 목록을 봅니다.

다음을 비교할 수 있습니다:

- 한 브랜치를 다른 브랜치와 비교합니다.
- 태그를 브랜치 또는 태그와 비교합니다.
- 커밋을 다른 커밋 또는 브랜치와 비교합니다.

## 비교 방법 {#compare-methods}

GitLab은 리비전을 비교하는 두 가지 방법을 제공합니다:

- **소스에서 들어오는 변경 사항만** (기본값): 두 리비전의 최신 공통 커밋 이후 소스에서의 차이를 표시합니다. 이 방법은 소스가 생성된 이후 대상에 대해 이루어진 관련 없는 변경 사항을 제외합니다. 이를 사용하여 소스 리비전으로 도입된 변경 사항만 봅니다.

  이 방법은 `git diff <from>...<to>` Git 명령을 사용합니다. 병합 베이스(공통 상위 커밋)에서 대상으로 비교하며, 실제 커밋을 직접 비교하는 대신 이 방법을 사용합니다.

- **소스 생성 이후 대상에 대한 변경 사항 포함**: 두 리비전 간의 모든 차이를 표시하며, 소스 및 대상 모두에 대한 변경 사항을 포함합니다. 이를 사용하여 리포지토리 기록의 두 시점 간 완전한 차이를 봅니다.

  이 방법은 `git diff <from> <to>` Git 명령을 사용합니다. 실제 커밋을 직접 비교하여 그 사이의 모든 변경 사항을 표시합니다.

## 브랜치, 태그 또는 커밋 비교 {#compare-branches-tags-or-commits}

리비전을 비교하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **리비전 비교**를 선택합니다.
1. **소스** 리비전을 선택합니다:

   - 브랜치를 검색하려면 브랜치 이름을 입력합니다. 정확한 일치 항목이 먼저 표시됩니다.
   - 태그를 검색하려면 태그 이름을 입력합니다.
   - 커밋을 검색하려면 커밋 SHA를 입력합니다.
   - 연산자로 검색을 구체화하려면:
     - `^`은 이름의 시작과 일치합니다: `^feat`은 `feat/user-authentication`과 일치합니다.
     - `$`은 이름의 끝과 일치합니다: `widget$`은 `feat/search-box-widget`과 일치합니다.
     - `*`은 와일드카드를 사용하여 일치합니다: `branch*cache*`은 `fix/branch-search-cache-expiration`과 일치합니다.
     - 연산자를 결합할 수 있습니다: `^chore/*migration$`은 `chore/user-data-migration`과 일치합니다.

1. **타겟** 리포지토리 및 리비전을 선택합니다.
1. **변경 사항 표시** 아래에서 **소스에서 들어오는 변경 사항만** (기본값) 또는 **소스 생성 이후 대상에 대한 변경 사항 포함**을 선택합니다.
1. **비교**를 선택합니다.
1. 선택 사항. **소스** 및 **타겟**을 반대로 하려면 **리비전 교체** ({{< icon name="substitute" >}})를 선택합니다.

비교 페이지는 리비전 간 변경된 커밋 및 파일 목록을 표시합니다.

## 환경에서 보기 {#view-on-environment}

리비전을 비교할 때 배포된 환경에서 직접 파일을 미리 볼 수 있습니다.

사전 요구 사항:

- 프로젝트에 대해 [경로 맵](../../../ci/review_apps/_index.md#route-maps)을 구성했습니다.
- 미리 보려는 파일이 경로 맵 구성에 포함되어 있습니다.
- 액세스 가능한 환경입니다.

배포된 환경에서 파일을 미리 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **리비전 비교**를 선택합니다.
1. 비교하려는 **소스** 및 **타겟** 브랜치 또는 커밋을 선택합니다.
1. 파일 diff 보기에서 경로 맵 구성에 포함된 파일을 찾습니다.
1. 파일에 대해 **추가 작업** 메뉴 ({{< icon name="ellipsis_v" >}})를 선택합니다.
1. **환경에서 보기 [environment name]**을 선택합니다.

파일이 새 탭에서 열리며, 배포된 환경에 표시되는 방식을 보여줍니다.

## 관련 항목 {#related-topics}

- [브랜치](branches/_index.md)
- [태그](tags/_index.md)
- [커밋](commits/_index.md)
- [Git 명령](../../../topics/git/commands.md)
