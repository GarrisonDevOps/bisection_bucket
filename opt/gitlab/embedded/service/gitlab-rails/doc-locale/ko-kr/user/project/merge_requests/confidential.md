---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 기밀 이슈에 대한 머지 리퀘스트를 정보 유출 없이 생성하는 방법.
title: 기밀 이슈에 대한 머지 리퀘스트
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

공개 리포지토리의 머지 리퀘스트도 공개되어 있으며, [기밀 이슈](../issues/confidential_issues.md)에 대한 머지 리퀘스트를 생성하는 경우에도 마찬가지입니다. 기밀 이슈에서 작업할 때 기밀 정보 유출을 방지하려면 동일한 네임스페이스의 비공개 포크에서 머지 리퀘스트를 생성하세요.

역할은 상위 그룹에서 상속됩니다. 원본 (공개) 리포지토리와 동일한 네임스페이스 (동일한 그룹 또는 하위 그룹)에 비공개 포크를 생성하면 개발자가 포크에서 동일한 권한을 받습니다. 이 상속은 다음을 보장합니다:

- 개발자 사용자는 기밀 이슈를 보고 해결하는 데 필요한 권한을 가집니다.
- 포크에 개별 사용자 액세스를 허용할 필요가 없습니다.

자세한 내용은 [GitLab 엔지니어용 패치 릴리스 런북](https://gitlab.com/gitlab-org/release/docs/blob/master/general/security/engineer.md)을 참조하세요.

## 기밀 머지 리퀘스트 생성 {#create-a-confidential-merge-request}

브랜치는 기본적으로 공개입니다. 작업의 기밀성을 보호하려면 동일한 네임스페이스에서 브랜치와 머지 리퀘스트를 생성해야 하지만 비공개 포크에서는 다운스트림에 생성해야 합니다. 공개 리포지토리와 동일한 네임스페이스에 비공개 포크를 생성하면 포크가 업스트림 공개 리포지토리의 권한을 상속합니다. 업스트림 공개 리포지토리에 개발자 역할을 가진 사용자는 사용자의 조치 없이 다운스트림 비공개 포크에서 해당 업스트림 권한을 상속합니다. 이러한 사용자는 기밀 이슈 해결을 돕기 위해 즉시 비공개 포크의 브랜치에 코드를 푸시할 수 있습니다.

> [!warning]
> 업스트림 리포지토리와 다른 네임스페이스에서 비공개 포크를 생성하면 기밀 정보가 노출될 수 있습니다. 두 네임스페이스는 동일한 사용자를 포함하지 않을 수 있습니다.

사전 요구 사항:

- 공개 리포지토리의 유지보수자 또는 소유자 역할을 가지고 있어야 합니다. [하위 그룹을 생성](../../group/subgroups/_index.md)하려면 이러한 역할 중 하나가 필요하기 때문입니다.
- 공개 리포지토리를 [포크](../repository/forking_workflow.md)했습니다.
- 포크에 **공개 수준**이 **비공개**입니다.

기밀 머지 리퀘스트를 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택하고 **유형** = **이슈**로 필터링한 후 이슈를 선택합니다.
1. 이슈 설명 아래로 스크롤한 후 **비공개 머지 리퀘스트 생성**을 선택합니다.
1. 필요에 맞는 항목을 선택합니다:
   - 브랜치와 머지 리퀘스트를 모두 생성하려면 **비공개 머지 리퀘스트와 브랜치 생성**을 선택합니다. 머지 리퀘스트는 공개 업스트림 프로젝트의 기본 브랜치가 아니라 포크의 기본 브랜치를 대상으로 합니다.
   - 브랜치만 생성하려면 **브랜치 생성**을 선택합니다.
1. **프로젝트**를 선택하여 사용합니다. 이러한 프로젝트는 머지 리퀘스트가 활성화되어 있으며, 이 프로젝트에서 개발자 역할 (이상)을 가지고 있습니다.
1. **브랜치 이름**을 입력하고 **소스 (브랜치 또는 태그)**를 선택합니다. GitLab은 이러한 브랜치가 비공개 포크에서 사용 가능한지 확인합니다. 두 브랜치 모두 선택한 포크에서 사용 가능해야 하기 때문입니다.
1. **생성**를 선택합니다.

이 머지 리퀘스트는 공개 업스트림 프로젝트가 아니라 비공개 포크를 대상으로 합니다. 브랜치, 머지 리퀘스트 및 커밋은 비공개 포크에 남아 있습니다. 이는 기밀 정보의 조기 공개를 방지합니다.

[포크에서 업스트림 리포지토리로](../repository/forking_workflow.md#merge-changes-back-upstream) 머지 리퀘스트를 열어야 할 때:

- 비공개 포크에서 문제가 해결되었다고 판단합니다.
- 기밀 커밋을 공개할 준비가 완료되었습니다.

## 관련 항목 {#related-topics}

- [기밀 이슈](../issues/confidential_issues.md)
- [에픽을 기밀로 만들기](../../group/epics/manage_epics.md#make-an-epic-confidential)
- [내부 노트 추가](../../discussions/_index.md#add-an-internal-note)
- [기밀 머지 리퀘스트에 대한 보안 관행](https://gitlab.com/gitlab-org/release/docs/blob/master/general/security/engineer.md#security-releases-critical-non-critical-as-a-developer) (GitLab)
