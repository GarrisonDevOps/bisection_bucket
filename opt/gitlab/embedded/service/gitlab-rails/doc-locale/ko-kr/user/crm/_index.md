---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 고객 관계 관리(CRM)
description: "고객 관리, 조직, 연락처 및 권한."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 17.7에서 최소 사용자 역할이 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

> [!note]
> 이 기능은 활발히 개발 중이지 않지만 [커뮤니티 기여](https://about.gitlab.com/community/contribute/)는 환영합니다. 기능이 요구 사항을 충족하는지 확인하려면 [에픽 5323](https://gitlab.com/groups/gitlab-org/-/epics/5323)의 미해결 작업 항목을 참조하세요.

고객 관리(CRM)를 사용하면 연락처(개인)와 조직(회사)의 기록을 생성하고 작업 항목에 연결할 수 있습니다.

기본적으로 연락처와 조직은 최상위 그룹에서만 생성할 수 있습니다. 다른 그룹에서 연락처와 조직을 생성하려면 [그룹을 연락처 출처로 할당](#configure-the-contact-source)하세요.

연락처와 조직을 사용하여 청구 및 보고 목적으로 작업을 고객에게 연결할 수 있습니다. 향후 계획된 내용에 대한 자세한 정보는 [이슈 2256](https://gitlab.com/gitlab-org/gitlab/-/issues/2256)을 참조하세요.

## 권한 {#permissions}

| 권한                         | Guest | Planner | 그룹 보고자 | 그룹 개발자, 유지 관리자 및 소유자 |
|------------------------------------|-------|---------|----------------|----------------------------------------|
| 연락처/조직 보기        |       | ✓       | ✓              | ✓                                      |
| 작업 항목 연락처 보기            |       | ✓       | ✓              | ✓                                      |
| 작업 항목 연락처 추가/제거      |       | ✓       | ✓              | ✓                                      |
| 연락처/조직 생성/편집 |       |         |                | ✓                                      |

## 고객 관리(CRM) 활성화 {#enable-customer-relations-management-crm}

고객 관리 기능은 그룹에 대해 켜져 있습니다. 서브그룹에서 CRM 기능을 사용하려면 서브그룹에 대해서도 켜야 합니다.

그룹 또는 서브그룹에서 고객 관리를 켜려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹 또는 하위 그룹을 찾습니다.
1. **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **고객 관리가 활성화되었습니다.**를 선택하세요.
1. **변경 사항 저장**을 선택합니다.

## 연락처 출처 구성 {#configure-the-contact-source}

{{< history >}}

- GitLab 17.6에서 [사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/167475)합니다.

{{< /history >}}

기본적으로 연락처는 작업 항목의 최상위 그룹에서 가져옵니다.

그룹의 연락처 출처는 자체 연락처 출처가 구성된 서브그룹을 제외한 모든 서브그룹에 적용됩니다.

그룹 또는 서브그룹의 연락처 출처를 구성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹 또는 하위 그룹을 찾습니다.
1. **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **연락처 출처** > **그룹 검색**을 선택하세요.
1. 연락처를 출처로 하려는 그룹을 선택하세요.
1. **변경 사항 저장**을 선택합니다.

## 연락처 {#contacts}

### 그룹에 연결된 연락처 보기 {#view-contacts-linked-to-a-group}

사전 요구 사항:

- 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

그룹의 연락처를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **고객 관리**를 선택하세요.

### 연락처 생성 {#create-a-contact}

사전 요구 사항:

- 그룹의 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

연락처를 생성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **고객 관리**를 선택하세요.
1. **새 연락처**를 선택하세요.
1. 필수 필드를 모두 작성하세요.
1. **새 연락처 생성**을 선택하세요.

GraphQL API를 사용하여 [연락처를 생성](../../api/graphql/reference/_index.md#mutationcustomerrelationscontactcreate)할 수도 있습니다.

### 연락처 편집 {#edit-a-contact}

사전 요구 사항:

- 그룹의 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

기존 연락처를 편집하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **고객 관리**를 선택하세요.
1. 편집하려는 연락처 옆에서 **편집** ({{< icon name="pencil" >}})을 선택하세요.
1. 필수 필드를 편집하세요.
1. **변경 사항 저장**을 선택합니다.

GraphQL API를 사용하여 [연락처를 편집](../../api/graphql/reference/_index.md#mutationcustomerrelationscontactupdate)할 수도 있습니다.

#### 연락처 상태 변경 {#change-the-state-of-a-contact}

각 연락처는 두 가지 상태 중 하나일 수 있습니다:

- **활성**: 이 상태의 연락처는 작업 항목에 추가할 수 있습니다.
- **비활성**: 이 상태의 연락처는 작업 항목에 추가할 수 없습니다.

연락처의 상태를 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **고객 관리**를 선택하세요.
1. 편집하려는 연락처 옆에서 **편집** ({{< icon name="pencil" >}})을 선택하세요.
1. **활성** 확인란을 선택하거나 선택 해제하세요.
1. **변경 사항 저장**을 선택합니다.

## 조직 {#organizations}

### 조직 보기 {#view-organizations}

사전 요구 사항:

- 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

그룹의 조직을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **고객 관리**를 선택하세요.
1. 오른쪽 위에서 **조직**을 선택하세요.

### 조직 생성 {#create-an-organization}

사전 요구 사항:

- 그룹의 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

조직을 생성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **고객 관리**를 선택하세요.
1. 오른쪽 위에서 **조직**을 선택하세요.
1. **새 조직**을 선택하세요.
1. 필수 필드를 모두 작성하세요.
1. **새 조직 생성**을 선택하세요.

GraphQL API를 사용하여 [조직을 생성](../../api/graphql/reference/_index.md#mutationcustomerrelationsorganizationcreate)할 수도 있습니다.

### 조직 편집 {#edit-an-organization}

사전 요구 사항:

- 그룹의 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

기존 조직을 편집하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **고객 관리**를 선택하세요.
1. 오른쪽 위에서 **조직**을 선택하세요.
1. 편집하려는 조직 옆에서 **편집** ({{< icon name="pencil" >}})을 선택하세요.
1. 필수 필드를 편집하세요.
1. **변경 사항 저장**을 선택합니다.

GraphQL API를 사용하여 [조직을 편집](../../api/graphql/reference/_index.md#mutationcustomerrelationsorganizationupdate)할 수도 있습니다.

## 티켓 {#tickets}

[Service Desk](../project/service_desk/_index.md)를 사용하고 이메일에서 티켓을 생성하면 티켓이 이메일의 발신자 및 참조(CC)의 이메일 주소와 일치하는 연락처에 연결됩니다.

### 연락처에 연결된 작업 항목 보기 {#view-work-items-linked-to-a-contact}

사전 요구 사항:

- 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

연락처의 작업 항목을 보려면 작업 항목 사이드바에서 연락처를 선택하거나:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **고객 관리**를 선택하세요.
1. 작업 항목을 보려는 연락처 옆에서 **작업 항목 보기** ({{< icon name="work-items" >}})를 선택하세요.

### 조직에 연결된 작업 항목 보기 {#view-work-items-linked-to-an-organization}

사전 요구 사항:

- 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

조직의 작업 항목을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **고객 관리**를 선택하세요.
1. 오른쪽 위에서 **조직**을 선택하세요.
1. 작업 항목을 보려는 조직 옆에서 **작업 항목 보기** ({{< icon name="work-items" >}})를 선택하세요.

### 작업 항목에 연결된 연락처 보기 {#view-contacts-linked-to-a-work-item}

사전 요구 사항:

- 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

작업 항목과 관련된 연락처를 오른쪽 사이드바에서 볼 수 있습니다.

연락처의 세부 정보를 보려면 연락처의 이름 위에 마우스를 올려놓으세요.

[GraphQL](../../api/graphql/reference/_index.md#mutationcustomerrelationsorganizationcreate) API를 사용하여 작업 항목 연락처를 볼 수도 있습니다.

### 작업 항목에 연락처 추가 {#add-contacts-to-a-work-item}

사전 요구 사항:

- 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

[활성](#change-the-state-of-a-contact) 연락처를 작업 항목에 추가하려면 [`/add_contacts` 빠른 작업](../project/quick_actions.md#add_contacts)을 사용하고 `[contact:address@example.com]`를 입력하세요.

[GraphQL](../../api/graphql/reference/_index.md#mutationissuesetcrmcontacts) API를 사용하여 작업 항목 연락처를 추가, 제거 또는 바꿀 수도 있습니다.

### 작업 항목에서 연락처 제거 {#remove-contacts-from-a-work-item}

사전 요구 사항:

- 그룹에 대해 계획자, 보고자, 개발자, 유지 보수자 또는 소유자 역할이 있어야 합니다.

작업 항목에서 연락처를 제거하려면 [`/remove_contacts` 빠른 작업](../project/quick_actions.md#remove_contacts)을 사용하고 `[contact:address@example.com]`를 입력하세요.

[GraphQL](../../api/graphql/reference/_index.md#mutationissuesetcrmcontacts) API를 사용하여 작업 항목 연락처를 추가, 제거 또는 바꿀 수도 있습니다.

## 연락처 자동 완성 {#autocomplete-contacts}

`/add_contacts` 빠른 작업을 사용할 때 `[contact:`를 따르면 [활성](#change-the-state-of-a-contact) 연락처의 자동 완성 목록이 나타납니다:

```plaintext
/add_contacts [contact:
```

`/remove_contacts` 빠른 작업을 사용할 때 `[contact:`를 따르면 작업 항목에 추가된 연락처의 자동 완성 목록이 나타납니다:

```plaintext
/remove_contacts [contact:
```

## CRM 항목을 포함한 개체 이동 {#moving-objects-with-crm-entries}

작업 항목 또는 프로젝트를 이동할 때 결과는 상위 그룹 연락처 출처에 따라 달라집니다:

- 출처가 일치하면 작업 항목이 연락처를 유지합니다.
- 출처가 변경되면 작업 항목이 연락처를 잃습니다.

[연락처 출처가 구성된](#configure-the-contact-source) 그룹을 이동하거나 연락처 출처가 변경되지 않은 경우 작업 항목이 연락처를 유지합니다.

그룹을 이동하고 연락처 출처를 변경하면:

- 모든 고유한 연락처와 조직이 새로운 최상위 그룹으로 이동됩니다.
- 이미 존재하는 연락처(이메일 주소로)는 중복으로 간주되어 삭제됩니다.
- 이미 존재하는 조직(이름으로)은 중복으로 간주되어 삭제됩니다.
- 모든 작업 항목이 연락처를 유지하거나 같은 이메일 주소의 연락처를 가리키도록 업데이트됩니다.

새로운 최상위 그룹에서 연락처와 조직을 생성할 권한이 없으면 그룹 전송이 실패합니다.
