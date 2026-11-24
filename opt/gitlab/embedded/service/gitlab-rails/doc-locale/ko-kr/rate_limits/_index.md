---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 속도 제한으로 GitLab에 대한 요청에서 인스턴스의 안정성과 보안을 보호합니다.
title: 속도 제한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!note]
> GitLab.com의 경우 [GitLab.com 관련 속도 제한](../user/gitlab_com/rate_limits.md#current-rate-limits)을 참조하세요.
>
> GitLab Dedicated의 경우 [인증된 사용자 속도 제한](../administration/dedicated/user_rate_limits.md)을 참조하세요.

속도 제한은 웹 애플리케이션의 보안과 내구성을 개선하는 데 사용되는 일반적인 기술입니다.

예를 들어 간단한 스크립트는 초당 수천 개의 웹 요청을 만들 수 있습니다. 요청은 다음과 같을 수 있습니다:

- 악의적입니다.
- 무관심합니다.
- 단순한 버그입니다.

애플리케이션과 인프라가 로드를 처리하지 못할 수 있습니다. 자세한 내용은 [서비스 거부 공격](https://en.wikipedia.org/wiki/Denial-of-service_attack)을 참조하세요. 대부분의 경우 단일 IP 주소에서의 요청 속도를 제한하여 완화할 수 있습니다.

대부분의 [무차별 대입 공격](https://en.wikipedia.org/wiki/Brute-force_attack)도 속도 제한으로 유사하게 완화됩니다.

> [!note]
> API 요청의 속도 제한은 프론트엔드에서 만든 요청에 영향을 주지 않습니다. 이러한 요청은 항상 웹 트래픽으로 계산되기 때문입니다.

## 구성 옵션 {#configuration-options}

**운영자** 영역에서 대부분의 속도 제한을 설정할 수 있습니다. 일부는 API 또는 Rails 콘솔을 통해서만 사용할 수 있으며, GitLab Pages 속도 제한은 구성 파일에서 설정합니다.

### 운영자 영역 {#admin-area}

인스턴스의 **운영자** 영역에서 다음 속도 제한을 설정할 수 있습니다:

- [API 속도 제한](api/_index.md)
- [콘텐츠 생성 속도 제한](content_creation.md)
- [Git 작업 속도 제한](git.md)
- [가져오기 및 내보내기 속도 제한](../administration/settings/import_export_rate_limits.md)
- [사고 관리 속도 제한](../administration/settings/incident_management_rate_limits.md)
- [파이프라인 생성 속도 제한](../administration/cicd/limits.md#pipeline-creation-rate-limits)
- [보호된 경로](../administration/settings/protected_paths.md)
- [원본 끝점 속도 제한](../administration/settings/rate_limits_on_raw_endpoints.md)
- [사용자 및 IP 속도 제한](../administration/settings/user_and_ip_rate_limits.md)
- [웹후크 작업 속도 제한](../administration/settings/rate-limit-on-webhook-operations.md)

### API 및 Rails 콘솔 {#api-and-rails-console}

[애플리케이션 설정 API](../api/settings.md)로 다음 속도 제한을 설정할 수 있습니다:

- [자동 완성 사용자 속도 제한](../administration/instance_limits.md#autocomplete-users-rate-limit)
- [AI 작업](../api/settings.md#available-settings) (`ai_action_api_rate_limit`): 인증된 사용자당 8시간당 160회 호출입니다. GraphQL `aiAction` 뮤테이션에 적용됩니다.
- [태그 생성 속도 제한](../api/settings.md#available-settings) (`tags_create_limit`): 프로젝트당 30분당 100개의 요청입니다. 태그를 생성하기 위한 REST API 끝점, GraphQL `tagCreate` 뮤테이션, UI의 태그 생성 및 `/tag` 빠른 작업에 적용됩니다.
- [파일 책임 추적 속도 제한](api/repository-files.md#configure-file-blame-rate-limits) (`project_repositories_blame_limit`, `project_repositories_blame_unauthenticated_limit`): 각 사용자 및 프로젝트당 1분마다 400개의 요청입니다. 인증되지 않은 요청은 각 IP 주소당 1분마다 400개의 요청으로 제한됩니다. 파일 책임 추적에 대한 REST API 끝점에 적용됩니다.

[플랜 제한 API](../api/plan_limits.md) 또는 [Rails 콘솔](../administration/operations/rails_console.md#starting-a-rails-console-session)로 이 속도 제한을 설정할 수 있습니다:

- [웹후크 속도 제한](../administration/instance_limits.md#webhook-rate-limit)

### 구성 파일 {#configuration-file}

예를 들어 Linux 패키지 설치에서 `/etc/gitlab/gitlab.rb` 구성 파일에서만 다음 속도 제한을 설정할 수 있습니다:

- [GitLab Pages 속도 제한](../administration/pages/rate-limits.md)

## 구성할 수 없는 제한 {#non-configurable-limits}

일부 속도 제한은 구성할 수 없습니다. 이러한 제한 목록은 [구성할 수 없는 속도 제한](non_configurable.md)을 참조하세요.

## 금지 및 차단 {#bans-and-blocks}

일부 보호는 요청을 느리게 하는 대신 일정 기간 동안 클라이언트를 차단합니다. 자세한 내용은 [악용 및 실패한 인증 금지](abuse_bans.md)를 참조하세요.

## 관련 항목 {#related-topics}

- [GitLab 애플리케이션 제한](../administration/instance_limits.md)
- [CI/CD 제한](../administration/cicd/limits.md)
