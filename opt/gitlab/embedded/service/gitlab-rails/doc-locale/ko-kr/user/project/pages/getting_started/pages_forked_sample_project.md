---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 포크된 샘플 프로젝트에서 GitLab Pages 웹사이트 만들기
description: 샘플 정적 사이트 생성기 프로젝트를 포크하여 GitLab Pages 웹사이트를 만듭니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab에서는 [가장 인기 있는 정적 사이트 생성기(SSG)의 샘플 프로젝트](https://gitlab.com/pages)를 제공합니다. 샘플 프로젝트 중 하나를 포크하고 CI/CD 파이프라인을 실행하여 Pages 웹사이트를 생성할 수 있습니다.

GitLab Pages를 테스트하거나 이미 Pages 사이트를 생성하도록 구성된 새 프로젝트를 시작하려면 샘플 프로젝트를 포크합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> [비디오 튜토리얼](https://www.youtube.com/watch?v=TWqh9MtT4Bg)을 시청하여 작동 방식을 알아봅니다.

샘플 프로젝트를 포크하고 Pages 웹사이트를 만들려면:

1. [GitLab Pages 예제](https://gitlab.com/pages) 그룹으로 이동하여 샘플 프로젝트를 확인합니다.
1. 포크할 프로젝트의 이름을 [포크](../../repository/forking_workflow.md#create-a-fork)합니다.
1. 오른쪽 상단 모서리에서 **포크**를 선택한 후 포크할 네임스페이스를 선택합니다.
1. 프로젝트의 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택한 후 **새 파이프라인**을 선택합니다. GitLab CI/CD가 사이트를 빌드하고 배포합니다.

사이트는 배포하는 데 약 30분이 걸릴 수 있습니다. 파이프라인이 완료되면 **배포** > **Pages**로 이동하여 Pages 웹사이트 링크를 찾습니다.

리포지토리에 푸시된 모든 변경 사항마다 GitLab CI/CD가 새 파이프라인을 실행하여 변경 사항을 Pages 사이트에 즉시 게시합니다.

## 포크 관계 제거 {#remove-the-fork-relationship}

포크한 프로젝트에 기여하려면 포크 관계를 유지할 수 있습니다. 그 외의 경우:

1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급** 설정을 확장합니다.
1. **포크 관계 제거**를 선택합니다.

## URL 변경 {#change-the-url}

URL을 네임스페이스와 일치하도록 변경할 수 있습니다. Pages 사이트가 GitLab.com에서 호스팅되는 경우 `<namespace>.gitlab.io`로 이름을 바꿀 수 있습니다. 여기서 `<namespace>`는 GitLab 네임스페이스입니다(프로젝트를 포크할 때 선택한 네임스페이스).

1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급**을 확장합니다.
1. **경로 변경**에서 경로를 `<namespace>.gitlab.io`로 업데이트합니다.

   예를 들어 프로젝트의 URL이 `gitlab.com/gitlab-tests/jekyll`인 경우 네임스페이스는 `gitlab-tests`입니다.

   리포지토리 경로를 `gitlab-tests.gitlab.io`로 설정하면 Pages 웹사이트의 결과 URL은 `https://gitlab-tests.gitlab.io`입니다.

   ![리포지토리 경로 변경](img/change_path_v12_10.png)

1. SSG 구성 파일을 열고 [기본 URL](../getting_started_part_one.md#urls-and-base-urls)을 `"project-name"`에서 `""`으로 변경합니다. 프로젝트 이름 설정은 SSG에 따라 다르며 구성 파일에 없을 수 있습니다.

## 관련 항목 {#related-topics}

- [작업 아티팩트 다운로드](../../../../ci/jobs/job_artifacts.md#download-job-artifacts)
