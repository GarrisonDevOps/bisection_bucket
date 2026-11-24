---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "GitLab에서 가장 일반적인 머지 리퀘스트 플로우는 포크, 보호된 브랜치 또는 둘 다를 사용합니다."
title: 머지 리퀘스트 워크플로
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 머지 리퀘스트는 일반적으로 다음 플로우 중 하나를 따릅니다:

- 단일 리포지토리에서 [보호된 브랜치](../repository/branches/protected.md)로 작업합니다.
- 공식 프로젝트의 포크로 작업합니다.

## 보호된 브랜치 플로우 {#protected-branch-flow}

보호된 브랜치 플로우를 사용하면 모든 사람이 포크 대신 동일한 GitLab 프로젝트에서 작업합니다.

프로젝트 유지관리자는 유지관리자 역할을 받고 일반 개발자는 개발자 역할을 받습니다.

유지관리자는 공식 브랜치를 '보호됨'으로 표시합니다.

개발자는 기능 브랜치를 프로젝트에 푸시하고 머지 리퀘스트를 생성하여 기능 브랜치를 검토하고 보호된 브랜치 중 하나로 병합하도록 합니다.

기본적으로 유지관리자 역할이 있는 사용자만 보호된 브랜치에 변경 사항을 병합할 수 있습니다.

- 장점:
  - 프로젝트가 적을수록 혼란이 적습니다.
  - 개발자는 하나의 원격 리포지토리만 고려하면 됩니다.
- 단점:
  - 각 새 프로젝트에 보호된 브랜치의 수동 설정이 필요합니다.

보호된 브랜치 플로우를 설정하려면:

1. 기본 브랜치가 [기본 브랜치 보호](../repository/branches/default.md)로 보호되도록 해야 합니다.
1. 팀에 여러 브랜치가 있고 변경 사항을 병합할 수 있는 사람과 명시적으로 푸시 또는 강제 푸시 옵션이 있는 사람을 관리하려면 해당 브랜치를 보호된 상태로 만드는 것을 고려하세요:

   - [브랜치 관리 및 보호](../repository/branches/_index.md#manage-and-protect-branches)
   - [보호된 브랜치](../repository/branches/protected.md)

1. 코드에 대한 각 변경 사항은 커밋으로 표시됩니다. 푸시 규칙으로 코드베이스에 들어오는 변경 사항에 대해 SSH 키 서명 필요와 같은 형식 및 보안 측정을 지정할 수 있습니다:

   - [푸시 규칙](../repository/push_rules.md)

1. 팀의 적절한 사람이 코드를 검토하고 확인하도록 하려면 다음을 사용하세요:

   - [코드 소유자](../codeowners/_index.md)
   - [머지 리퀘스트 승인 규칙](approvals/rules.md)

Ultimate 티어에서도 사용 가능:

- [상태 확인](status_checks.md)
- [보안 승인](approvals/rules.md#security-approvals)

## 포크 워크플로 {#forking-workflow}

포크 워크플로를 사용하면 유지관리자는 공식 리포지토리에서 유지관리자 역할을 받고 일반 개발자는 보고자 역할을 받으며, 이는 이들이 변경 사항을 푸시하는 것을 금지합니다.

개발자는 공식 프로젝트의 포크를 생성하고 기능 브랜치를 자신의 포크로 푸시합니다.

변경 사항을 기본 브랜치로 가져오려면 포크 전체에서 머지 리퀘스트를 생성해야 합니다.

- 장점:
  - 적절하게 구성된 GitLab 그룹에서 새 프로젝트는 자동으로 일반 개발자에게 필요한 액세스 제한을 받습니다. 새 프로젝트에 대한 인증을 구성하는 수동 단계가 더 적습니다.
- 단점:
  - 프로젝트는 포크를 최신 상태로 유지해야 하므로 더 고급 Git 기술(여러 원격 관리)이 필요합니다.
