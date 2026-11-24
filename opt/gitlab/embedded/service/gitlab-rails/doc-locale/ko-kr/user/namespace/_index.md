---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 네임스페이스
description: 네임스페이스의 다양한 유형에 대해 자세히 알아봅니다.
---

네임스페이스는 GitLab에서 프로젝트를 구성합니다. 각 네임스페이스가 별도이기 때문에 여러 네임스페이스에서 같은 프로젝트 이름을 사용할 수 있습니다.

네임스페이스 이름을 선택할 때 다음을 기억하세요:

- [명명 규칙](../reserved_names.md#rules-for-usernames-project-and-group-names-and-slugs)
- [예약된 그룹 이름](../reserved_names.md#reserved-group-names)

> [!note]
> 마침표가 있는 네임스페이스(`.`)는 SSL 인증서 유효성 검사 및 [Terraform 모듈 발행](../packages/terraform_module_registry/_index.md#publish-a-terraform-module) 시 소스 경로에 문제를 일으킵니다.

## 네임스페이스 유형 {#types-of-namespaces}

GitLab에는 두 가지 유형의 네임스페이스가 있습니다:

- **사용자**: 개인 네임스페이스는 사용자 이름을 기반으로 합니다. 개인 네임스페이스에서:
  - 서브그룹을 만들 수 없습니다.
  - 속한 그룹은 개인 네임스페이스 권한이나 기능을 상속하지 않습니다.
  - 만드는 모든 프로젝트는 이 네임스페이스의 범위에 있습니다.
  - 사용자 이름을 변경하면 프로젝트 및 네임스페이스 URL도 변경됩니다. 사용자 이름을 변경하기 전에 [리포지토리 리디렉트](../project/repository/_index.md#repository-path-changes)에 대해 읽어보세요.

- **그룹**: 그룹 또는 서브그룹 네임스페이스는 그룹 또는 서브그룹 이름을 기반으로 합니다. 그룹 및 서브그룹 네임스페이스에서:
  - 여러 프로젝트를 관리하기 위해 여러 서브그룹을 만들 수 있습니다.
  - 서브그룹은 상위 그룹 설정 중 일부를 상속합니다. 이를 서브그룹 **설정**에서 볼 수 있습니다.
  - 각 서브그룹 및 프로젝트에 대해 설정을 구체적으로 구성할 수 있습니다.
  - 그룹 또는 서브그룹 URL을 이름과 독립적으로 관리할 수 있습니다.

## 어떤 유형의 네임스페이스인지 확인 {#determine-which-type-of-namespace-youre-in}

그룹 또는 개인 네임스페이스인지 확인하려면 URL을 볼 수 있습니다. 예를 들어:

| 네임스페이스 대상 | URL | 네임스페이스 |
| ------------- | --- | --------- |
| `alex`이라는 사용자입니다. | `https://gitlab.example.com/alex` | `alex` |
| `alex-team`이라는 그룹입니다. | `https://gitlab.example.com/alex-team` | `alex-team` |
| `alex-team`이라는 그룹에 `marketing`이라는 서브그룹이 있습니다. |  `https://gitlab.example.com/alex-team/marketing` | `alex-team/marketing` |

## 네임스페이스 ID 확인 {#determine-the-namespace-id}

네임스페이스 ID는 그룹 ID 또는 프로젝트 ID입니다. 그룹과 상호 작용하려면 그룹 ID를 사용하고 프로젝트와 상호 작용하려면 프로젝트 ID를 사용합니다.

UI에서 그룹 및 프로젝트 ID를 찾을 수 있습니다:

- [그룹 ID 찾기](../group/_index.md#find-the-group-id).
- [프로젝트 ID 찾기](../project/working_with_projects.md#find-the-project-id).
