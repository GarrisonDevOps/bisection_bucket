---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Harbor 레지스트리
description: Harbor 컨테이너 레지스트리를 GitLab 프로젝트 또는 그룹과 통합하세요.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- **Harbor 레지스트리**는 **운영** 메뉴 섹션에서 **배포**로 GitLab 17.0에서 [이동](https://gitlab.com/gitlab-org/gitlab/-/issues/439494)했습니다.

{{< /history >}}

[Harbor 컨테이너 레지스트리](../../project/integrations/harbor.md)를 GitLab과 통합하고 Harbor를 GitLab 프로젝트의 컨테이너 레지스트리로 사용하여 이미지를 저장할 수 있습니다.

## Harbor 레지스트리 보기 {#view-the-harbor-registry}

프로젝트 또는 그룹의 Harbor 레지스트리를 볼 수 있습니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Harbor 레지스트리**를 선택하세요.

이 페이지에서 이미지를 검색, 정렬, 필터링할 수 있습니다. 브라우저에서 URL을 복사하여 필터링된 보기를 공유할 수 있습니다.

프로젝트 수준에서 오른쪽 위 모서리에 **CLI 명령어**가 표시되며, 여기서 로그인, 이미지 빌드 및 푸시에 필요한 해당 명령어를 복사할 수 있습니다. **CLI 명령어**는 그룹 수준에서 표시되지 않습니다.

> [!note]
> 프로젝트 수준의 Harbor 통합을 위한 기본 설정은 그룹 수준에서 상속됩니다.

## Harbor 레지스트리에서 이미지 사용 {#use-images-from-the-harbor-registry}

GitLab Harbor 레지스트리에 호스팅된 Harbor 이미지를 다운로드하고 실행하려면:

1. 컨테이너 이미지 링크를 복사하세요:
   1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
   1. **배포** > **Harbor 레지스트리**를 선택하고 원하는 이미지를 찾으세요.
   1. 이미지 이름 옆의 **복사** 아이콘을 선택하세요.

1. 원하는 컨테이너 이미지를 실행하는 명령어를 사용하세요.

## 특정 아티팩트의 태그 보기 {#view-the-tags-of-a-specific-artifact}

특정 아티팩트와 연결된 태그 목록을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. **배포** > **Harbor 레지스트리**로 이동하세요.
1. 이미지 이름을 선택하여 해당 아티팩트를 봅시다.
1. 원하는 아티팩트를 선택하세요.

그러면 태그 목록이 표시됩니다. 태그 수와 게시된 시간을 볼 수 있습니다.

태그 URL을 복사하고 이를 사용하여 해당 아티팩트를 가져올 수도 있습니다.

## 명령어를 사용하여 이미지 빌드 및 푸시 {#build-and-push-images-by-using-commands}

Harbor 레지스트리에 빌드하고 푸시하려면:

1. Harbor 레지스트리로 인증하세요.
1. 빌드 또는 푸시 명령어를 실행하세요.

이러한 명령어를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Harbor 레지스트리**를 선택하세요.
1. **CLI 명령어**를 선택하세요.

## 프로젝트의 Harbor 레지스트리 비활성화 {#disable-the-harbor-registry-for-a-project}

프로젝트의 Harbor 레지스트리를 제거하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **활성 중인 통합** 아래에서 **Harbor**를 선택하세요.
1. **통합 활성화**에서 **활성** 확인란을 선택 취소합니다.
1. **변경 사항 저장**을 선택합니다.

**배포** > **Harbor 레지스트리** 항목은 사이드바에서 제거됩니다.
