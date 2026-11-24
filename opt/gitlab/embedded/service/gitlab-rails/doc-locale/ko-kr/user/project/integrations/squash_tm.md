---
stage: Plan
group: Portfolio Planning
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Squash TM
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Squash TM](https://www.squashtest.com/en/squash-gitlab-platform) (테스트 관리) 통합이 GitLab에서 활성화되고 구성되면, GitLab에서 생성된 이슈(일반적으로 사용자 스토리)는 Squash TM의 요구사항으로 동기화되며, 테스트 진행률이 GitLab 이슈에 보고됩니다.

<i class="fa-youtube-play" aria-hidden="true"></i> DevSecOps 워크플로우를 Squash TM 및 GitLab 통합으로 최적화하는 방법에 대한 개요는 [SDLC에서 요구사항 및 테스트 관리 활용](https://www.youtube.com/watch?v=XAiNUmBiqm4)을 참조하세요.
<!-- Video published on 2024-05-15 -->

## Squash TM 구성 {#configure-squash-tm}

1. 선택 사항. 시스템 관리자에게 [속성 파일에서 토큰을 구성](https://tm-en.doc.squashtest.com/latest/redirect/gitlab-integration-token.html)하도록 요청합니다.
1. [Squash TM 설명서](https://tm-en.doc.squashtest.com/latest/redirect/gitlab-integration-configuration.html)를 참조하여 다음을 수행합니다:
   1. GitLab 서버를 생성합니다.
   1. `Xsquash4GitLab` 플러그인을 활성화합니다.
   1. 동기화를 구성합니다.
   1. **실시간 동기화** 패널에서 다음 필드를 복사하여 나중에 GitLab에서 사용합니다:

      - **Webhook URL**.
      - **비밀 토큰**(1단계에서 Squash TM 시스템 관리자가 구성한 경우).

## GitLab 구성 {#configure-gitlab}

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Squash TM**을 선택합니다.
1. **활성** 토글이 활성화되어 있는지 확인합니다.
1. **트리거** 섹션에서 실시간 동기화의 영향을 받는 이슈 유형을 나타냅니다.
1. 필드를 완성합니다:

   - **Squash TM webhook URL**을 입력합니다.
   - **비밀 토큰**을 입력합니다(Squash TM 시스템 관리자가 이전에 구성한 경우).
