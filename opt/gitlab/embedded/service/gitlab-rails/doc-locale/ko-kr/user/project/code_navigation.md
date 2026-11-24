---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 코드 탐색
description: GitLab Orbit의 지식 그래프를 사용하여 심볼이 정의되고 호출되는 위치를 찾습니다.
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com
- 상태:  베타

{{< /details >}}

{{< history >}}

- [베타](../../policy/development_stages_support.md#beta)로 GitLab 19.0에서 `orbit_code_intelligence`라는 [기능 플래그](../../administration/feature_flags/_index.md)와 함께 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/234404)되었습니다. 기본적으로 비활성화되었습니다.
- [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/599054) GitLab 19.4에서입니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

코드 네비게이션을 사용하면 생소한 코드를 이해하고 프로젝트의 나머지 부분과의 연결을 파악할 수 있습니다.

코드 네비게이션은 [GitLab Orbit](https://docs.gitlab.com/orbit/indexed-data/)이 코드로부터 빌드하고 변경 사항을 푸시할 때 업데이트되는 지식 그래프를 읽습니다. 해당 그래프에서 프로젝트의 파일, 클래스, 모듈, 메서드, 함수 및 이러한 심볼이 서로 호출하는 방식을 읽습니다. 인덱서 또는 CI/CD 작업이 필요하지 않습니다.

선택된 심볼의 경우 코드 네비게이션에는 다음이 표시됩니다:

- 참조: 이 심볼을 호출하는 프로젝트의 위치(호출자 수로도 표시됨)입니다.
- 호출: 이 심볼이 호출하는 심볼입니다.
- 정의: 심볼이 정의된 파일 및 줄로의 링크입니다.

## 파일의 코드 네비게이션 보기 {#view-code-navigation-for-a-file}

사전 요구 사항:

- 프로젝트의 리포터, 개발자, 유지보수자 또는 소유자 역할입니다.
- 프로젝트의 최상위 그룹에 대해 [GitLab Orbit이 활성화됨](https://docs.gitlab.com/orbit/remote/getting-started/)입니다.
- 프로젝트의 기본 브랜치에 있는 파일입니다. GitLab Orbit은 다른 브랜치를 인덱싱하지 않습니다.

파일의 코드 네비게이션을 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택합니다.
1. 기본 브랜치에서 파일을 선택합니다.
1. 파일의 오른쪽 위 모서리에서 **코드 네비게이션** ({{< icon name="code" >}})을 선택합니다.

최상위 그룹에 대해 GitLab Orbit을 최근에 활성화한 경우 [인덱싱](https://docs.gitlab.com/orbit/remote/indexing/)이 진행 중일 수 있습니다. 인덱싱이 완료되면 패널에 심볼이 나열됩니다.

심볼이 사용되는 위치를 확인하려면:

1. 패널에서 심볼을 선택합니다.
1. **참조**를 선택하여 이를 호출하는 심볼을 보거나 **호출**을 선택하여 이것이 호출하는 심볼을 봅니다.
1. 결과를 선택하여 일치하는 줄에서 해당 파일을 엽니다.

심볼 목록으로 돌아가려면 **심볼로 돌아가기**를 선택합니다.

## 지원되는 언어 {#supported-languages}

코드 네비게이션은 GitLab Orbit이 인덱싱하는 언어를 포함합니다. 현재 목록은 [GitLab Orbit](https://docs.gitlab.com/orbit/) 설명서를 참조하세요.
