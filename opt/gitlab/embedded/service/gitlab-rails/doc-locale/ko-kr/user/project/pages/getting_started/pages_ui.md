---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 정적 사이트용 GitLab Pages 배포 생성
description: 안내식 UI 양식을 사용하여 정적 사이트 또는 프레임워크 기반 애플리케이션을 GitLab Pages에 배포합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Pages 배포를 생성하여 정적 사이트 또는 프레임워크를 GitLab에서 호스팅되는 웹사이트로 변환합니다. 단계별 양식을 통해 GitLab은 다음을 수행합니다:

- 프로젝트 설정을 기반으로 사용자 지정 CI/CD 구성을 생성합니다.
- GitLab Pages 배포를 위해 `.gitlab-ci.yml` 파일을 구성합니다.
- 머지 리퀘스트를 통해 검토할 변경 사항을 제출합니다.
- 머지 리퀘스트가 병합될 때 자동으로 웹사이트를 배포합니다.

Pages UI를 사용하여 정적 사이트 또는 프레임워크 기반 애플리케이션을 배포할 수 있습니다.

## 사전 요구 사항 {#prerequisites}

- 앱은 [파일을 `public` 폴더에 출력](../public_folder.md)해야 합니다. 빌드 파이프라인 중에 이 폴더를 만드는 경우 Git에 커밋할 필요가 없습니다.

  > [!warning]
  > 이 단계는 중요합니다. 파일이 루트 수준 `public` 폴더에 있는지 확인하세요.

- 다음 중 하나를 만족하는 프로젝트가 있어야 합니다:
  - [Eleventy](https://www.11ty.dev), [Astro](https://astro.build) 또는 [Jekyll](https://jekyllrb.com)과 같은 정적 사이트 또는 클라이언트 렌더링 단일 페이지 애플리케이션(SPA)을 생성합니다.
  - [Next.js](https://nextjs.org), [Nuxt](https://nuxt.com) 또는 [SvelteKit](https://kit.svelte.dev)과 같은 정적 출력을 위해 구성된 프레임워크를 포함합니다.
- 프로젝트에 대해 GitLab Pages를 켜야 합니다. (켜려면 **설정** > **일반**으로 이동하고, **표시 여부, 프로젝트 기능, 권한**을 확장한 다음, **Pages** 토글을 켜세요.)

## Pages 배포 생성 {#create-the-pages-deployment}

설정을 완료하고 GitLab Pages 배포를 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.

   **Pages 시작** 양식이 나타납니다. 이 양식을 사용할 수 없으면 [문제 해결](#if-the-get-started-with-pages-form-is-not-available)을 참조하세요.
1. **1 단계**에서 이미지 이름을 입력합니다. [Pages로 배포할 사용자 지정 폴더 설정](../introduction.md#customize-the-default-folder)할 수도 있습니다.
1. **다음**을 선택합니다.
1. **2 단계**에서 설치 단계를 입력합니다. 프레임워크의 빌드 프로세스에 제공된 빌드 명령 중 하나가 필요하지 않은 경우 다음 중 하나를 수행할 수 있습니다:
   - **다음**을 선택하여 단계를 건너뜁니다.
   - `:` (bash "아무것도 하지 않음" 명령)을 입력하면 해당 단계의 보일러플레이트를 `.gitlab-ci.yml` 파일에 계속 포함하고 싶을 때 사용할 수 있습니다.
1. **다음**을 선택합니다.
1. **3 단계**에서 애플리케이션을 빌드하는 방법을 나타내는 스크립트를 입력합니다.
1. **다음**을 선택합니다.
1. 선택 사항. 생성된 `.gitlab-ci.yml` 파일을 필요에 따라 편집합니다.
1. **4 단계**에서 커밋 메시지를 추가하고 **커밋**을 선택합니다. 이 커밋은 첫 번째 GitLab Pages 배포를 트리거합니다.

실행 중인 파이프라인을 보려면 **빌드** > **파이프라인**으로 이동합니다. 파이프라인이 성공하면 Pages 사이트가 배포되고 액세스할 수 있게 됩니다.

배포 중에 생성된 아티팩트를 보려면 작업을 보고 오른쪽에서 **아티팩트 다운로드**를 선택합니다.

## 배포 URL 보기 {#view-deployment-url}

파이프라인이 성공적으로 완료된 후:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. **배포**에서 활성 배포 URL을 볼 수 있습니다.
1. 배포된 GitLab Pages 사이트를 방문하려면 URL을 선택합니다.

> [!note]
> 파이프라인이 완료된 후 사이트가 사용 가능하게 될 때까지 몇 분 정도 걸릴 수 있습니다.

## 문제 해결 {#troubleshooting}

### `Get Started with Pages` 양식을 사용할 수 없는 경우 {#if-the-get-started-with-pages-form-is-not-available}

`Get Started with Pages` 양식은 다음의 경우 사용할 수 없습니다:

- 이전에 GitLab Pages 사이트를 배포했습니다.
- 양식을 통해 최소 한 번 이상 `.gitlab-ci.yml`을 커밋했습니다.

이 문제를 해결하려면:

- **Pages 파이프라인이 완료될 때까지 기다리는 중** 메시지가 나타나면 **다시 시작**을 선택하여 양식을 다시 시작합니다.
- 프로젝트가 이전에 GitLab Pages를 성공적으로 배포했으면 [수동으로 업데이트](pages_from_scratch.md)하여 `.gitlab-ci.yml` 파일을 업데이트합니다.
