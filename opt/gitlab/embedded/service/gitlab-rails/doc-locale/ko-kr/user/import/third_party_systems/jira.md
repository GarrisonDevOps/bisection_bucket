---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>.
title: Jira에서 마이그레이션
description: Jira에서 마이그레이션하는 옵션
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Jira를 사용하는 경우 다음 중 하나를 선택할 수 있습니다:

- Jira에서 마이그레이션하지 않고 GitLab에서 새로 시작합니다. 그러면 GitLab 사용의 이점을 최대화하기 위해 프로세스와 워크플로우 설정에 집중할 수 있습니다.
- 여러 옵션 중 하나를 사용하여 Jira에서 GitLab으로 마이그레이션합니다.

| 마이그레이션 옵션             | 설명 |
|:-----------------------------|:------------|
| GitLab Professional Services | [GitLab Professional Services](https://about.gitlab.com/services/)에서 마이그레이션을 수행하도록 합니다. |
| `Jira2Lab`                   | [`Jira2Lab`](https://about.gitlab.com/blog/seamlessly-migrate-from-jira-to-gitlab-with-jira2lab-at-scale/)를 사용합니다. GitLab Professional Services에서 `jira2gitlab`를 포크했습니다. |
| 타사 스크립트           | 예를 들어 마이그레이션을 위해 [`jira2gitlab`](https://github.com/swingbit/jira2gitlab)를 사용합니다. |
| Jira 임포터                | [Jira 임포터 사용](#use-the-jira-importer) \- GitLab에 기본 제공됩니다. |
| CSV 파일 가져오기              | [CSV 파일 사용](#use-a-csv-file) \- Jira에서 GitLab으로 데이터를 옮깁니다. |
| 자신의 스크립트              | [자신의 스크립트 작성](#write-your-own-script) \- GitLab REST 또는 GraphQL API를 사용합니다. |
| 타사 서비스          | GitLab과 Jira를 동기화된 상태로 유지하는 타사 서비스(예: [Unito](https://marketplace.atlassian.com/apps/1218054/gitlab-2-way-integration-for-jira) 및 [Getint](https://marketplace.atlassian.com/apps/1223999/gitlab-integration-for-jira-two-way-sync-forge))를 사용합니다. |

## Jira 임포터 사용 {#use-the-jira-importer}

Jira 임포터를 사용하면 Jira 이슈를 GitLab으로 가져올 수 있습니다. 여러 Jira 프로젝트의 이슈를 GitLab 프로젝트로 가져올 수 있습니다. GitLab은 이슈의 제목, 설명 및 레이블을 직접 가져옵니다. 임포트를 준비할 때 Jira 사용자를 GitLab 프로젝트 멤버에 매핑할 수도 있습니다.

GitLab 이슈 필드에 공식적으로 매핑되지 않는 다른 Jira 이슈 메타데이터는 GitLab 이슈의 설명으로 일반 텍스트로 가져옵니다.

Jira 이슈의 텍스트는 GitLab Flavored Markdown으로 파싱되지 않아 텍스트 형식이 손상될 수 있습니다. 자세한 내용은 [이슈 379104](https://gitlab.com/gitlab-org/gitlab/-/issues/379104)를 참조하세요.

[에픽 2738](https://gitlab.com/groups/gitlab-org/-/epics/2738)은 이슈 담당자, 댓글 및 GitLab Jira 임포터의 기타 개선 사항 추가를 제안합니다.

### 사전 요구 사항 {#prerequisites}

- Jira 이슈에 대한 읽기 액세스 권한과 가져올 GitLab 프로젝트의 유지 관리자 또는 소유자 역할이 필요합니다.
- GitLab [Jira 이슈 통합](../../../integration/jira/_index.md)을 구성합니다.

### Jira 이슈 가져오기 {#import-jira-issues}

Jira 이슈 가져오기는 비동기 백그라운드 작업으로 수행되며, 다음에 따라 지연이 발생할 수 있습니다:

- 임포트 대기열 로드입니다.
- 시스템 로드입니다.
- 기타 요소입니다.

큰 프로젝트 가져오기는 가져오기 크기에 따라 몇 분이 걸릴 수 있습니다.

Jira 이슈를 GitLab 프로젝트로 가져오려면:

1. {{< icon name="work-items" >}} **작업 항목** 페이지에서 **조치** ({{< icon name="ellipsis_v" >}}) > **Jira에서 가져오기**를 선택합니다.
1. **다음에서 가져오기** 드롭다운 목록을 선택하고 이슈를 가져올 Jira 프로젝트를 선택합니다.

   **Jira-GitLab 사용자 매핑 템플릿** 섹션에서 테이블은 Jira 사용자가 어느 GitLab 사용자에게 매핑되는지 보여줍니다. 양식이 나타나면 드롭다운 목록이 기본값으로 임포트를 수행하는 사용자로 설정됩니다.

1. 매핑을 변경하려면 **GitLab 사용자명** 열에서 드롭다운 목록을 선택하고 각 Jira 사용자에게 매핑할 사용자를 선택합니다.

   드롭다운 목록에 모든 사용자가 표시되지 않을 수 있으므로 검색 표시줄을 사용하여 이 GitLab 프로젝트에서 특정 사용자를 찾습니다.

1. **계속**을 선택합니다. 임포트가 시작되었다는 확인을 받습니다.

   임포트가 백그라운드에서 실행되는 동안 **작업 항목** 페이지로 이동하여 새 이슈(이슈 유형의 작업 항목)가 목록에 나타나는 것을 볼 수 있습니다.

1. 임포트 상태를 확인하려면 Jira 임포트 페이지로 다시 이동합니다.

## CSV 파일 사용 {#use-a-csv-file}

CSV 파일에서 Jira 이슈 데이터를 GitLab 프로젝트로 가져오려면:

1. Jira 데이터 내보내기:
   1. Jira 인스턴스에 로그인하고 마이그레이션하려는 프로젝트로 이동합니다.
   1. 프로젝트 데이터를 CSV 파일로 내보냅니다.
   1. CSV 파일을 [GitLab CSV 임포터에 필요한 열 이름](../../project/issues/csv_import.md)과 일치하도록 편집합니다.
      - `title`, `description`, `due_date` 및 `milestone`만 가져옵니다.
      - 임포트 프로세스 중에 다른 이슈 메타데이터를 자동으로 설정하려면 설명 필드에 [빠른 동작](../../project/quick_actions.md)을 추가할 수 있습니다.
1. 새 GitLab 그룹 및 프로젝트 만들기:
   1. GitLab 계정에 로그인하고 마이그레이션된 프로젝트를 호스팅할 [그룹을 만듭니다](../../group/_index.md#create-a-group).
   1. 새 그룹에서 마이그레이션된 Jira 이슈를 보유할 [새 프로젝트를 만듭니다](../../project/_index.md#create-a-blank-project).
1. Jira 데이터를 GitLab으로 임포트합니다:
   1. 새 GitLab 프로젝트의 왼쪽 사이드바에서 **계획** > **작업 항목**을 선택합니다.
   1. **조치** ({{< icon name="ellipsis_v" >}}) > **Jira에서 가져오기**를 선택합니다.
   1. 화면의 지시를 따르고 임포트 프로세스를 완료합니다.
1. 마이그레이션 확인:
   1. 가져온 이슈를 검토하여 프로젝트가 GitLab으로 성공적으로 마이그레이션되었는지 확인합니다.
   1. 마이그레이션된 Jira 프로젝트의 기능을 GitLab에서 테스트합니다.
1. 워크플로우 및 설정 조정:
   1. GitLab [프로젝트 설정](../../project/settings/_index.md)을 사용자 지정합니다. 예를 들어:
      - [설명 템플릿](../../project/description_templates.md).
      - [레이블](../../project/labels.md).
      - [마일스톤](../../project/milestones/_index.md).
   1. 팀에게 GitLab 인터페이스와 마이그레이션으로 인해 도입된 새로운 워크플로우 또는 프로세스에 대해 숙지하도록 합니다.
1. 마이그레이션에 만족하면 Jira 인스턴스를 폐기하고 GitLab으로 완전히 전환할 수 있습니다.

## 자신의 스크립트 작성 {#write-your-own-script}

마이그레이션 프로세스를 완전히 제어하려면 Jira 이슈를 GitLab으로 마이그레이션하는 자신의 커스텀 스크립트를 작성할 수 있습니다. 이렇게 하면 필요에 정확히 맞는 방식으로 마이그레이션할 수 있습니다. GitLab은 마이그레이션을 자동화하기 위한 API를 제공합니다:

- [REST API](../../../api/rest/_index.md)
- [GraphQL API](../../../api/graphql/_index.md)

시작하려면 다음 GitLab API 엔드포인트를 숙지하세요:

- [이슈](../../../api/issues.md)
- [프로젝트](../../../api/projects.md)
- [레이블](../../../api/labels.md)
- [마일스톤](../../../api/milestones.md)

스크립트를 작성할 때 Jira 이슈 필드를 해당 GitLab 동등물에 매핑해야 합니다.

| Jira 이슈 필드 | 가능한 GitLab 동등물 |
|:----|:-------|
| 고정된 옵션 수를 포함하는 사용자 지정 필드 | [범위 지정 레이블](../../project/labels.md#scoped-labels)을 만듭니다. 필드 이름을 범위 지정 레이블 키로, 필드 값을 범위 지정 레이블 세트 값으로 설정합니다. 예를 들어 `input name::value1`, `input name::value2`입니다. |
| 텍스트 문자열 또는 정수 값을 포함하는 사용자 지정 필드 | 사용자 지정 필드 이름과 값을 이슈의 설명 섹션에 삽입합니다. |
| 상태 | [상태](../../work_items/status.md)를 사용합니다. |
| 우선순위 | [범위 지정 레이블](../../project/labels.md#scoped-labels)을 만듭니다. 우선순위를 범위 지정 레이블 키로, 우선순위 값을 범위 지정 레이블 세트 값으로 설정합니다. 예를 들어, `priority::1`입니다. |
| 스토리 포인트 | 이 값을 GitLab 이슈의 **가중치** 값으로 매핑합니다. |
| 스프린트 | 이 값을 GitLab 이슈의 **이터레이션** 값으로 매핑합니다. 이 값은 완료되지 않았거나 향후 스프린트로 예약된 이슈에만 의미가 있습니다. 데이터를 임포트하기 전에 프로젝트의 부모 그룹에 필요한 [이터레이션](../../group/iterations/_index.md#iteration-cadences)을 만듭니다. |

Atlassian Document Format 파싱 및 GitLab Flavored Markdown으로 매핑을 처리해야 할 수도 있습니다. 다양한 방식으로 이에 접근할 수 있습니다. 영감을 얻으려면 [예시 커밋을 검토](https://gitlab.com/gitlab-org/gitlab/-/commit/4292a286d3f4ab26466f8e89125a4dbd194a9f3e)하세요. 이 커밋은 Jira 임포터를 위해 Atlassian Document Format을 GitLab Flavored Markdown으로 파싱하는 메서드를 추가했습니다.

GitLab을 로컬로 실행하는 경우 Rails 콘솔에서 Atlassian Document Format을 GitLab Flavored Markdown으로 수동으로 변환할 수도 있습니다. 이렇게 하려면 다음을 실행합니다:

```ruby
text = <document in Atlassian Document Format>
project = <project that wiki is in> or nil
Banzai.render(text, pipeline: :adf_commonmark, project: project)
```

## 관련 항목 {#related-topics}

- [설정 가져오기 및 내보내기](../../../administration/settings/import_and_export_settings.md)
- [임포트를 위한 Sidekiq 구성](../../../administration/sidekiq/configuration_for_imports.md)
- [여러 Sidekiq 프로세스 실행](../../../administration/sidekiq/extra_sidekiq_processes.md)
- [특정 작업 클래스 처리](../../../administration/sidekiq/processing_specific_job_classes.md)
