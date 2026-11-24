---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab에서 사용 가능한 커밋 squashing 옵션을 이해하고 구성합니다.
title: 스쿼시 및 머지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Squash and merge는 여러 개의 작은 커밋을 하나의 의미 있는 커밋으로 결합합니다. 이 전략은 리포지토리 기록을 깔끔하게 유지하고 변경 사항을 추적하거나 되돌리기 쉽게 만듭니다. 여러 기능에서 동시에 작업하는 경우, squashing은 각 기능의 변경 사항을 서로 다른 논리 단위로 분리합니다.

- 작은 커밋들이 함께 결합되어 [변경 사항의 모든 부분을 되돌리기](revert_changes.md)가 더 간단해집니다.
- 단일 커밋이 대상 브랜치에 병합될 때, 전체 커밋 기록이 유지됩니다.
- 기본 브랜치는 깔끔하게 유지되며, 의미 있는 커밋 메시지를 포함합니다.

## Squash and merge 워크플로 {#squash-and-merge-workflow}

브랜치가 기본 브랜치로 병합될 때마다 최대 두 개의 커밋이 추가됩니다:

- 브랜치의 커밋을 squashing하여 만든 단일 커밋입니다.
- 프로젝트에서 [fast-forward merge](methods/_index.md#fast-forward-merge)를 활성화하지 않은 한 merge 커밋입니다. Fast-forward merge는 추가 merge 커밋의 생성을 방지하지만, 브랜치의 커밋을 단일 커밋으로 squashing할 수 있습니다.

기본적으로 squashed 커밋은 다음 메타데이터를 포함합니다:

- 메시지: squash 커밋의 설명 또는 사용자 정의 메시지
- 작성자: 병합 요청을 만든 사용자
- 커미터: squash를 시작한 사용자

프로젝트 소유자는 모든 squash 커밋과 merge 커밋에 대해 [새로운 기본 메시지를 만들](commit_templates.md) 수 있습니다.

## 병합 요청에 대한 기본 squash 옵션 설정 {#set-default-squash-options-for-a-merge-request}

병합 요청을 만들거나 편집할 권한이 있는 사용자는 병합 요청에 대한 기본 squash 옵션을 설정할 수 있습니다.

사전 요구 사항:

- 프로젝트는 squashing을 허용하거나 권장하도록 [구성](#configure-squash-options-for-a-project)되어야 합니다.

다음과 같이 설정합니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**를 선택하고 병합 요청을 찾습니다.
1. **편집**을 선택합니다.
1. **병합 요청이 수락될 때 커밋 squash** 체크박스를 선택하거나 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

## 병합 요청에서 커밋 squash {#squash-commits-in-a-merge-request}

프로젝트에서 병합 요청에 대한 squashing 옵션을 선택할 수 있는 경우, merge 프로세스의 일부로 커밋을 squash하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**를 선택하고 병합 요청을 찾습니다.
1. merge 리퀘스트 위젯에서 **Squash commits** 체크박스가 선택되었는지 확인합니다. 프로젝트의 squashing 옵션이 **허용하지 않음** 또는 **요구**로 설정된 경우 이 체크박스가 표시되지 않습니다.
1. 선택 사항. squash 커밋 메시지 또는 merge 커밋 메시지(프로젝트 구성에 따라)를 수정하려면 **커밋 메시지 수정**을 선택합니다.
1. 병합 요청이 병합할 준비가 되면 **머지**를 선택합니다.

## 프로젝트에 대한 squash 옵션 구성 {#configure-squash-options-for-a-project}

사전 요구 사항:

- 이 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

프로젝트의 모든 병합 요청에 대한 기본 squashing 동작을 구성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **머지할 때 커밋 스쿼시** 섹션에서 원하는 동작을 선택합니다:
   - **허용하지 않음**: Squashing이 수행되지 않으며 옵션이 표시되지 않습니다.
   - **허용**: Squashing이 허용되지만 기본적으로 선택 해제됩니다.
   - **권장**: Squashing이 허용되고 기본적으로 선택되지만 비활성화할 수 있습니다.
   - **요구**: Squashing이 항상 수행됩니다. 병합 요청은 squash 옵션을 표시하지만 사용자는 이를 변경할 수 없습니다.
1. **변경 사항 저장**을 선택합니다.

## 장기 실행 브랜치 동작 {#long-running-branch-behavior}

장기 실행 브랜치를 squash and merge하지 않아야 합니다. 대신, merge 커밋이나 fast-forward merge와 같이 원본 커밋 기록을 유지하는 [merge 방법](methods/_index.md)을 사용합니다.

새 커밋을 계속 수신하는 브랜치를 squash and merge하면, 브랜치 기록이 대상 브랜치와 달라집니다. Squashing은 다른 SHA를 가진 대상 브랜치에 새로운 단일 커밋을 만듭니다. 대상 브랜치를 rebase하거나 merge하지 않고 소스 브랜치에서 계속 작업하면 Git은 기록이 달라진 것으로 처리합니다.

해당 소스 브랜치에서 새 병합 요청을 열면 다음을 볼 수 있습니다:

- 이전 병합 요청에서 이미 병합된 커밋입니다.
- 소스 브랜치가 대상 브랜치 뒤에 있다는 경고입니다.

diff는 대상 브랜치에 아직 없는 새로운 변경 사항만 올바르게 표시합니다.

squash merge 후 장기 실행 브랜치를 대상과 동기화된 상태로 유지하려면:

- 각 merge 후 소스 브랜치를 대상 브랜치에서 rebase합니다.
- 각 merge 후 대상 브랜치를 소스 브랜치로 다시 merge합니다.

## 관련 항목 {#related-topics}

- [커밋 메시지 템플릿](commit_templates.md)
- [머지 방법](methods/_index.md)
