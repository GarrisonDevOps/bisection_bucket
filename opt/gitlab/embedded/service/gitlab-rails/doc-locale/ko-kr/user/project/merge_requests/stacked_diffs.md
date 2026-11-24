---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 작은 머지 변경사항을 스택으로 쌓아서 최종적으로 기능을 전달하려면 스택된 diff를 사용합니다.
title: 스택된 Diffs
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- [GitLab CLI v1.42.0](https://gitlab.com/gitlab-org/cli/-/releases/v1.42.0)에서 [실험](../../../policy/development_stages_support.md#experiment)으로 릴리스되었습니다.

{{< /history >}}

[GitLab CLI](https://docs.gitlab.com/cli/)에서 스택된 diff를 사용하여 서로 쌓아올리는 작은 변경사항을 만들어 최종적으로 기능을 전달합니다. 각 스택은 별도이므로 다음을 수행할 수 있습니다:

- 이전 변경사항을 검토하는 동안 새로운 기능을 계속 빌드합니다.
- 다른 작업에 영향을 주지 않고 특정 diff에 대한 검토 피드백에 응답합니다.
- 승인된 diff를 독립적으로 머지합니다.

스택된 diff의 워크플로우는 다음과 같습니다:

1. 변경사항 생성: `glab stack save`을 실행하면 GitLab CLI는:

   - 모든 변경사항을 스테이징합니다.
   - 메시지와 함께 새로운 커밋을 생성합니다.
   - 이 커밋에 대해 새로운 브랜치를 생성합니다.
   - 자동으로 새 브랜치로 이동합니다.

1. GitLab에 동기화: `glab stack sync`을 실행하면 GitLab CLI는:

   - 스택의 모든 브랜치를 GitLab에 푸시합니다.
   - 아직 병합 요청이 없는 각 diff에 대해 병합 요청을 생성합니다.
   - 병합 요청을 함께 연결합니다. 첫 번째를 제외한 각 병합 요청은 이전 diff 브랜치를 대상으로 합니다.

CLI의 이 기능에 대한 기본 명령은 [`stack`](https://docs.gitlab.com/cli/stack/)이며, 이를 [다른 명령](#available-commands)으로 확장합니다.

<div class="video-fallback">
  자세히 알아보려면 다음을 참조하세요: <a href="https://www.youtube.com/watch?v=TOQOV8PWYic">CLI의 스택된 diff 개요</a>
</div>
<figure class="video-container">
  <iframe src="https://www.youtube-nocookie.com/embed/TOQOV8PWYic" frameborder="0" allowfullscreen> </iframe>
</figure>
<!-- Video published on 2024-06-18 -->

이 기능은 [실험](../../../policy/development_stages_support.md)입니다. [이슈 7473](https://gitlab.com/gitlab-org/cli/-/issues/7473)에서 피드백을 공유해 주세요.

## 스택된 diff 생성 {#create-a-stacked-diff}

대규모 기능을 더 작고 검토 가능한 변경사항으로 나누려면 스택된 diff를 생성합니다.

사전 요구 사항:

- [GitLab CLI](https://docs.gitlab.com/cli/)를 설치하고 인증해야 합니다.

스택된 diff를 생성하려면:

1. 터미널에서 새 스택을 생성하고 이름을 지정합니다. 예를 들어:

   ```shell
   glab stack create add-authentication
   ```

1. 편집기에서 첫 번째 변경사항 집합을 만듭니다.
1. 첫 번째 diff로 변경사항을 저장합니다:

   ```shell
   glab stack save
   ```

   메시지가 표시되면 이 변경사항을 설명하는 커밋 메시지를 입력합니다.

1. 다음 변경사항 집합을 만들고 두 번째 diff로 저장합니다:

   ```shell
   glab stack save
   ```

   `glab stack save`을 실행할 때마다 새로운 diff와 브랜치를 생성합니다. 메시지가 표시되면 이 변경사항을 설명하는 커밋 메시지를 입력합니다.

1. GitLab에 변경사항을 푸시하고 병합 요청을 생성할 준비가 되면 다음을 실행합니다:

   ```shell
   glab stack sync
   ```

병합 요청은 검토를 위해 준비되어 있습니다. 이 스택에서 더 많은 diff를 계속 생성하거나 다른 작업으로 전환할 수 있습니다.

## 스택의 diff에 변경사항 추가 {#add-changes-to-a-diff-in-a-stack}

스택의 특정 지점으로 돌아가서 더 많은 변경사항을 추가하려면:

1. 스택 목록을 표시합니다:

   ```shell
   glab stack move
   ```

1. 편집할 스택을 선택하고 <kbd>Enter</kbd>를 누릅니다.
1. 변경 사항을 만듭니다.
1. 준비가 되면 변경사항을 저장하고 다음을 실행합니다:

   ```shell
   glab stack amend
   ```

1. 선택 사항. 스택의 설명을 변경합니다.
1. 변경사항을 푸시합니다:

   ```shell
   glab stack sync
   ```

기존 스택을 동기화할 때 GitLab은:

- 새 변경사항으로 기존 스택을 업데이트합니다.
- 최신 변경사항을 가져오기 위해 스택의 다른 병합 요청을 리베이스합니다.

## 사용 가능한 명령 {#available-commands}

스택된 diff로 작업할 때 이 명령들을 사용합니다:

| 명령                                               | 설명 |
|-------------------------------------------------------|-------------|
| [`create`](https://docs.gitlab.com/cli/stack/create/) | 새 스택을 생성합니다. |
| [`save`](https://docs.gitlab.com/cli/stack/save/)     | 새 diff로 변경사항을 저장합니다. |
| [`amend`](https://docs.gitlab.com/cli/stack/amend/)   | 현재 diff를 수정합니다. |
| [`prev`](https://docs.gitlab.com/cli/stack/prev/)     | 이전 diff로 이동합니다. |
| [`next`](https://docs.gitlab.com/cli/stack/next/)     | 다음 diff로 이동합니다. |
| [`first`](https://docs.gitlab.com/cli/stack/first/)   | 첫 번째 diff로 이동합니다. |
| [`last`](https://docs.gitlab.com/cli/stack/last/)     | 마지막 diff로 이동합니다. |
| [`move`](https://docs.gitlab.com/cli/stack/move/)     | 목록에서 모든 diff를 선택합니다. |
| [`sync`](https://docs.gitlab.com/cli/stack/sync/)     | 브랜치를 푸시하고 병합 요청을 생성/업데이트합니다. |

### save와 amend 중에서 선택 {#choose-between-save-and-amend}

다양한 목적을 위해 다음 명령을 사용합니다:

- `glab stack save`: 새로운 diff(커밋과 브랜치)를 생성합니다. 스택에 새로운 논리적 변경사항을 추가할 때 이를 사용합니다.
- `glab stack amend`: 현재 diff를 수정합니다. 검토 피드백에 응답하거나 현재 변경사항을 수정할 때 이를 사용합니다.

## 관련 항목 {#related-topics}

- [스택된 병합 요청](reviews/stacked_merge_requests.md)
