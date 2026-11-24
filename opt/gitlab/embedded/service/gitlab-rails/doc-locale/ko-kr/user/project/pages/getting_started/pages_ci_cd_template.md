---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: CI/CD 템플릿으로 GitLab Pages 웹사이트 만들기
description: 정적 사이트 생성기용 CI/CD 템플릿으로 GitLab Pages 웹사이트를 만듭니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab는 가장 인기 있는 정적 사이트 생성기(SSG)를 위한 `.gitlab-ci.yml` 템플릿을 제공합니다. 이러한 템플릿 중 하나에서 자체 `.gitlab-ci.yml` 파일을 만들고 CI/CD 파이프라인을 실행하여 Pages 웹사이트를 생성할 수 있습니다.

Pages 사이트를 추가하려는 기존 프로젝트가 있을 때 `.gitlab-ci.yml` 템플릿을 사용합니다.

GitLab 리포지토리에는 SSG 관련 파일 또는 순수 HTML이 포함되어야 합니다. 이 단계를 완료한 후 Pages 사이트가 제대로 생성되도록 추가 구성을 수행해야 할 수 있습니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **추가** ({{< icon name="plus" >}}) 드롭다운 목록에서 **새 파일**을 선택합니다.
1. **파일명** 텍스트 상자에 `.gitlab-ci.yml`을(를) 입력합니다. 텍스트 상자의 오른쪽에 드롭다운 목록이 나타납니다.
1. **템플릿 적용** 드롭다운 목록의 **Pages** 섹션에서 SSG의 이름을 선택합니다. 순수 HTML의 경우 **HTML**을 선택합니다.
1. **커밋 메시지** 텍스트 상자에 커밋 메시지를 입력합니다.
1. **변경 사항 커밋**을 선택합니다.

모든 것이 제대로 구성되면 사이트 배포에 약 30분이 소요될 수 있습니다.

파이프라인을 보려면 **빌드** > **파이프라인**으로 이동합니다.

파이프라인이 완료되면 **배포** > **Pages**로 이동하여 Pages 웹사이트의 링크를 찾습니다.

리포지토리에 푸시되는 모든 변경 사항에 대해 GitLab CI/CD는 새 파이프라인을 실행하고 변경 사항을 Pages 사이트에 즉시 게시합니다.

사이트를 위해 생성된 HTML 및 기타 자산을 보려면 [작업 아티팩트 다운로드](../../../../ci/jobs/job_artifacts.md#download-job-artifacts)합니다.
