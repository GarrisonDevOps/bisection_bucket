---
stage: AI Clients
group: Duo Chat
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab Duo Chat를 찾는 위치와 이슈 작업에 사용하는 방법을 설명합니다.
title: "자습서: GitLab Duo Chat으로 이슈 관리하기"
---

GitLab Duo Agentic Chat은 에이전트라는 AI 어시스턴트를 사용하여 특정 작업을 완료하고 복잡한 질문에 답하도록 돕습니다. 이 튜토리얼에서는 GitLab Duo Chat 인터페이스를 익히는 데 도움이 되는 다음 작업을 완료합니다:

- 기본 GitLab Duo 에이전트에 일반적인 질문을 하도록 요청합니다.
- Planner 에이전트를 사용하여 더 복잡한 이슈 관리 작업을 완료합니다. 구체적으로:
  - 이슈에서 높은 우선순위의 버그를 찾아 필터링합니다.
  - 사용자에게 할당된 이슈를 찾고 필요한 작업을 하위 항목으로 분할합니다.

## 시작하기 전에 {#before-you-begin}

- [GitLab Duo Agent Platform 전제 조건](../../user/duo_agent_platform/_index.md#prerequisites)을 충족해야 합니다.
- [기본 GitLab Duo 네임스페이스](../../user/profile/preferences.md#set-a-default-gitlab-duo-namespace)를 설정해야 합니다.
- 잘 알고 있는 프로젝트를 선택합니다. 사용자에게 할당된 열린 이슈가 최소한 하나 이상 있어야 합니다.

## GitLab Duo Chat 열기 {#open-gitlab-duo-chat}

먼저 채팅 인터페이스를 익히고 첫 채팅을 시작합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. GitLab Duo 사이드바 오른쪽에서 **새 채팅 추가**를 선택합니다.
1. 이제 사용할 에이전트를 선택합니다. 일반적인 질문을 하려면 **GitLab Duo**를 선택합니다.

   ![채팅 시작 및 에이전트 선택](img/add_new_chat_v18_9.png)

GitLab Duo 패널이 화면 오른쪽에서 튕겨져 나옵니다. 패널은 GitLab을 탐색할 때 열려 있어서 채팅하는 동안 코드, 이슈 또는 머지 리퀘스트를 참조할 수 있습니다.

![GitLab Duo 패널의 새로운 빈 채팅](img/chat_panel_v18_9.png)

패널 하단의 채팅 텍스트 상자 근처에서 사용할 대규모 언어 모델을 선택할 수 있습니다. 이 튜토리얼에서는 기본 선택을 유지할 수 있습니다.

![모델 선택기](img/choose_model_v18_9.png)

이제 시도해 보세요!

1. 채팅 텍스트 상자에 입력합니다:

   ```plaintext
   Give me an overview of this project's architecture.
   ```

1. <kbd>Enter</kbd>를 누르거나 **전송**을 선택합니다.

GitLab Duo가 패널에 결과를 요약합니다.

## 이슈 찾기 및 필터링 {#find-and-filter-issues}

이제 프로젝트에서 특정 이슈를 검색해 봅니다. 프로젝트에서 모든 높은 우선순위의 버그를 식별하려고 합니다.

이 작업을 위해 Planner 에이전트로 전환합니다.

1. GitLab Duo 사이드바에서 **새 채팅 추가** > **플래너**를 선택합니다.
1. 채팅 텍스트 상자에 입력합니다:

   ```plaintext
   List all open issues labeled 'bug' and 'high-priority' created in the last 30 days.
   ```

1. <kbd>Enter</kbd>를 누르거나 **전송**을 선택합니다.

Planner 에이전트가 프로젝트를 검색하고 기준에 따라 이슈를 필터링합니다. 제목, 이슈 번호 및 링크가 있는 일치하는 이슈 목록을 받게 됩니다.

다음으로 다양한 레이블, 날짜 범위 또는 기타 기준으로 필터링할 후속 프롬프트를 시도해 봅니다. 예를 들어:

```plaintext
Order this list by date created, and then alphabetically by name.
```

## 이슈 분석 및 하위 항목 만들기 {#analyze-an-issue-and-create-subtasks}

Chat을 사용하여 사용자에게 할당된 이슈 목록을 보고 하나를 더 자세히 분석합니다.

1. Planner 에이전트 대화에서 채팅 텍스트 상자에 입력합니다:

   ```plaintext
   Show me all the open issues assigned to me.
   ```

1. <kbd>Enter</kbd>를 누르거나 **전송**을 선택합니다.
1. 이슈 중 하나를 선택합니다. 이제 Planner 에이전트를 사용하여 하위 항목을 만들어 작업을 더 관리하기 쉬운 단계로 분할합니다.

   하위 항목이 필요하지 않더라도 걱정하지 마세요. 나중에 항상 닫을 수 있습니다.
1. 채팅 텍스트 상자에 입력합니다:

   ```plaintext
   Analyze issue #<selected_issue_number> and suggest how to break up the work into two or three subtasks.
   ```

1. <kbd>Enter</kbd>를 누르거나 **전송**을 선택합니다.
1. 제안된 하위 항목을 검토하고 동의하면 입력합니다:

   ```plaintext
   Create these subtasks as child items under issue #<selected_issue_number>.
   ```

   또는 후속 프롬프트를 사용하여 만족할 때까지 추가 개선을 요청합니다.
1. <kbd>Enter</kbd>를 누르거나 **전송**을 선택합니다.
1. GitLab Duo가 최종 검토를 위해 작업 항목을 준비합니다. 설명과 JSON 요청 매개 변수를 읽은 다음 **승인**을 선택합니다.

   ![GitLab Duo가 준비한 작업 항목 승인](img/approve_chat_v18_9.png)

이슈가 이슈의 하위 항목으로 추가되고 채팅 패널에 링크가 표시됩니다. 그런 다음 레이블을 추가하거나 이슈를 할당하거나 마일스톤을 설정할 수 있습니다.

## 다음 단계 {#next-steps}

축하합니다! GitLab Duo Chat과 Planner 에이전트를 간단한 이슈 관리에 사용하는 방법을 배웠습니다.

예를 들어 하위 항목의 세부 사항을 계속 반복할 수 있습니다:

- `Can you provide more detail on task 3?`
- `Split task 2 into separate tasks`
- `Add technical implementation notes to these tasks`

또는 이것을 실험으로 시도 중인 경우 하위 항목을 닫을 수 있습니다:

```plaintext
Close these subtasks and add a comment in each that says: "This subtask was created as part of a tutorial exercise."
```

완료한 작업을 검토하려면 이전 채팅으로 돌아갈 수 있습니다. GitLab Duo 사이드바에서 **GitLab Duo 채팅 이력** ({{< icon name="history" >}})을 선택합니다.

![채팅 이력 목록](img/chat_history_v18_9.png)
