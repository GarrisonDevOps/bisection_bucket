---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 이슈 교차 연결
description: "커밋 메시지, 연결된 이슈, 머지 리퀘스트 및 브랜치 이름에서 이슈를 서로 연결하여 관련 작업을 추적합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

교차 연결은 GitLab의 이슈 간에 관계를 만듭니다. 교차 연결:

- 더 나은 추적 및 표시를 위해 관련 이슈를 연결합니다.
- 이슈를 관련 커밋 및 머지 리퀘스트에 연결합니다.
- 커밋 메시지, 브랜치 이름 및 설명을 통해 참고 자료를 만듭니다.
- 프로젝트 및 그룹 전체에서 작동합니다.
- 각 이슈의 **링크된 항목** 섹션에서 관계를 표시합니다.

다음을 통해 교차 연결을 만들 수 있습니다:

- [커밋 메시지](#from-commit-messages)
- [연결된 이슈](#from-linked-issues)
- [머지 리퀘스트](#from-merge-requests)
- [브랜치 이름](#from-branch-names)
- [명시적 작업 항목 링크](../../work_items/_index.md#work-items-in-merge-requests)

## 커밋 메시지에서 {#from-commit-messages}

커밋 메시지에서 이슈를 언급할 때마다 개발 워크플로우의 두 단계 사이에 관계를 만드는 것입니다. 이슈 자체와 그 이슈와 관련된 첫 커밋 사이의 관계입니다.

이슈와 커밋하는 코드가 모두 같은 프로젝트에 있으면 커밋 메시지에 `#xxx`을 추가합니다. 여기서 `xxx`은 이슈 번호입니다.

```shell
git commit -m "this is my commit message. Ref #xxx"
```

커밋 메시지는 보통 `#` 문자로 시작할 수 없으므로 대신 `GL-xxx` 표기법을 사용할 수도 있습니다:

```shell
git commit -m "GL-xxx: this is my commit message"
```

다른 프로젝트에 있지만 같은 그룹에 있으면 커밋 메시지에 `projectname#xxx`을 추가합니다.

```shell
git commit -m "this is my commit message. Ref projectname#xxx"
```

같은 그룹에 없으면 이슈의 전체 URL(`https://gitlab.com/<username>/<projectname>/-/issues/<xxx>`)을 추가할 수 있습니다.

> [!note]
> 성능상의 이유로 GitLab은 커밋 메시지의 처음 1,000개 전체 URL만 자동 연결을 위해 처리합니다. 이 제한을 초과하는 추가 URL은 링크로 변환되지 않습니다.

```shell
git commit -m "this is my commit message. Related to https://gitlab.com/<username>/<projectname>/-/issues/<xxx>"
```

물론 `gitlab.com`을 자신의 GitLab 인스턴스의 URL로 바꿀 수 있습니다.

첫 커밋을 이슈에 연결하는 것은 [GitLab 가치 스트림 분석](https://about.gitlab.com/solutions/value-stream-management/)으로 프로세스를 추적하는 데 중요합니다. 이는 이슈를 만드는 것과 첫 커밋을 만드는 것 사이의 시간인 그 이슈의 구현 계획에 소요된 시간을 측정합니다.

## 연결된 이슈에서 {#from-linked-issues}

머지 리퀘스트 및 다른 이슈에서 연결된 이슈를 언급하면 팀 구성원과 협력자가 같은 주제에 대한 열린 이슈가 있음을 알 수 있습니다.

이슈 `#222`에서 이슈 `#111`을 언급하면 이슈 `#111`도 **활동** 피드에 알림을 표시합니다. 즉, 관계를 한 번만 언급하면 두 이슈 모두에 표시됩니다. [머지 리퀘스트](#from-merge-requests)에서 이슈를 언급할 때도 동일합니다.

이슈의 활동 피드가 **이력만 표시** 또는 **모든 활동 보기**로 필터링되면 교차 연결은 `(Username) mentioned in issue #(number) (time ago)`로 표시됩니다.

## 머지 리퀘스트에서 {#from-merge-requests}

머지 리퀘스트 댓글에서 이슈를 언급하는 것은 [연결된 이슈](#from-linked-issues)에서와 정확히 같은 방식으로 작동합니다.

머지 리퀘스트 설명에서 이슈를 언급하면 [이슈와 머지 리퀘스트를 함께 연결합니다](#from-linked-issues). 또한 머지 리퀘스트가 병합되는 즉시 [이슈를 자동으로 종료하도록 설정](managing_issues.md#closing-issues-automatically)할 수도 있습니다.

이슈의 활동 피드가 **이력만 표시** 또는 **모든 활동 보기**로 필터링되면 교차 연결은 `(Username) mentioned in merge request !(number) (time ago)`로 표시됩니다.

## 브랜치 이름에서 {#from-branch-names}

이슈와 같은 프로젝트에서 브랜치를 만들고 브랜치 이름을 이슈 번호로 시작한 후 하이픈을 붙이면 만드는 이슈와 MR이 연결됩니다. 자세한 내용은 [브랜치 이름을 이슈 번호로 시작](../repository/branches/_index.md#prefix-branch-names-with-a-number)을 참조하세요.
