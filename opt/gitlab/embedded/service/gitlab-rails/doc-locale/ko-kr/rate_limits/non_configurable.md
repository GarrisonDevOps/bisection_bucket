---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab 애플리케이션에서 고정된 속도 제한입니다.
title: 구성 불가능한 속도 제한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab은 애플리케이션에서 다음 속도 제한을 적용합니다.

| 한도                                | 속도 제한                                                     | 세부 정보 |
|:-------------------------------------|:---------------------------------------------------------------|:--------|
| AI 카탈로그 일괄 활성화               | 각 인증된 사용자당 분당 10개 요청                  | `aiCatalogItemConsumerBulkCreate` GraphQL 뮤테이션에 적용되며, 이를 통해 [에이전트를 활성화](../user/duo_agent_platform/agents/custom.md#enable-an-agent)하거나 여러 프로젝트에서 한 번에 [플로우를](../user/duo_agent_platform/flows/custom.md#enable-a-flow) 사용할 수 있습니다. [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/265715)에서 도입되었습니다. |
| AI 카탈로그 비활성화                   | 각 인증된 사용자당 분당 30개 요청            | `aiCatalogItemConsumerDelete` GraphQL 뮤테이션에 적용되며, 이를 통해 프로젝트 또는 최상위 그룹에서 [에이전트를 비활성화](../user/duo_agent_platform/agents/custom.md#disable-an-agent)하거나 [플로우를](../user/duo_agent_platform/flows/custom.md#disable-a-flow) 사용할 수 있습니다. [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/266155)에서 도입되었습니다. |
| AI 카탈로그 활성화                    | 각 인증된 사용자당 분당 30개 요청            | `aiCatalogItemConsumerCreate` GraphQL 뮤테이션에 적용되며, 이를 통해 프로젝트 또는 최상위 그룹에서 [에이전트를 활성화](../user/duo_agent_platform/agents/custom.md#enable-an-agent)하거나 [플로우를](../user/duo_agent_platform/flows/custom.md#enable-a-flow) 사용할 수 있습니다. [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/266155)에서 도입되었습니다. |
| AI 모델 선택 업데이트            | 인증된 사용자당 분당 30개 요청                  | `aiModelSelectionNamespaceUpdate` GraphQL 뮤테이션에 적용되며, 이는 GitLab.com의 최상위 그룹에서 GitLab Duo 기능이 사용하는 모델을 선택합니다. [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/265318)에서 도입되었으며 [기능 플래그](../administration/feature_flags/_index.md) `ai_model_selection_namespace_update_rate_limit`라고 이름이 지어집니다. 기본적으로 비활성화되었습니다. |
| 변경 로그 생성                 | 사용자당 프로젝트당 분당 5개 호출                        | `:id/repository/changelog` 엔드포인트에 적용됩니다. 제한은 `GET` 및 `POST` 작업 간에 공유됩니다. |
| 커밋 diff 파일                    | 분당 6개 요청                                          | 확장된 커밋 diff 파일(`/[group]/[project]/-/commit/[:sha]/diff_files?expanded=1`)에 적용됩니다. 인증된 요청의 경우 사용자당, 인증되지 않은 요청의 경우 IP 주소당 제한이 적용됩니다. |
| CSV 내보내기                           | 인증된 사용자당 분당 6개 요청                   | UI에서 그리고 `workItemsCsvExport`, `mergeRequestsCsvExport` 및 `exportRequirements` GraphQL 뮤테이션을 통해 이슈, 작업 항목, 머지 리퀘스트 및 요구 사항을 CSV로 내보내는 것에 적용됩니다. 제한은 이들 간에 공유됩니다. GitLab 19.6에서 도입되었으며 [기능 플래그](../administration/feature_flags/_index.md) `issuable_csv_export_rate_limit`라고 이름이 지어집니다. 기본적으로 비활성화되었습니다. |
| 배포 삭제                  | 인증된 사용자당 분당 500개 요청                 | [배포 삭제](../api/deployments.md#delete-a-deployment)에 `DELETE /projects/:id/deployments/:deployment_id`을(를) 통해 적용됩니다. 대규모 배포 삭제의 인프라 영향을 줄입니다. GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/243738)되었습니다. |
| FogBugz 가져오기                       | 사용자당 분당 1개의 트리거된 가져오기                         | FogBugz에서 프로젝트 가져오기를 트리거하는 것에 적용됩니다. GitLab 17.6에서 도입되었습니다. |
| 그룹 삭제                       | 인증된 사용자당 분당 60개 요청                  | [삭제할 그룹 예약](../api/groups.md#schedule-a-group-for-deletion)에 `DELETE /groups/:id`을(를) 통해 적용됩니다. `permanently_remove`을(를) 사용하는 요청은 삭제를 즉시 시작하기 때문에 분당 10개 요청으로 별도로 제한됩니다. [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/263606)에서 도입되었으며 [기능 플래그](../administration/feature_flags/_index.md) `group_and_project_delete_rate_limit`이(가) 이름이 지어집니다. 기본적으로 비활성화되었습니다. |
| Slack용 GitLab 앱 이벤트          | Slack 워크스페이스당 분당 60개 요청                     | Slack이 `POST /integrations/slack/events`로 전송하는 이벤트(예: GitLab Duo에 대한 멘션 및 직접 메시지)에 적용됩니다. 제한을 초과하는 요청은 확인되고 삭제됩니다. [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/work_items/631397)에서 도입되었으며 [기능 플래그](../administration/feature_flags/_index.md) `slack_app_workspace_rate_limit`이(가) 이름이 지어집니다. 기본적으로 비활성화되었습니다. |
| Slack용 GitLab 앱 상호 작용    | Slack 워크스페이스당 분당 300개 요청                    | `POST /integrations/slack/interactions` 및 `POST /integrations/slack/options`에 적용됩니다. 제한을 초과하는 요청은 확인되고 삭제됩니다. [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/work_items/631397)에서 도입되었으며 [기능 플래그](../administration/feature_flags/_index.md) `slack_app_workspace_rate_limit`이(가) 이름이 지어집니다. 기본적으로 비활성화되었습니다. |
| Slack용 GitLab 앱 슬래시 명령  | Slack 워크스페이스당 분당 60개 요청                     | `POST /slack/trigger`에 적용됩니다. 제한을 초과하는 슬래시 명령은 실행되지 않으며 오류 메시지가 표시됩니다. [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/work_items/631397)에서 도입되었으며 [기능 플래그](../administration/feature_flags/_index.md) `slack_app_workspace_rate_limit`이(가) 이름이 지어집니다. 기본적으로 비활성화되었습니다. |
| 새 사용자 계정                    | IP 주소당 분당 20개 호출                             | `/users/sign_up` 엔드포인트에 적용됩니다. 사용 중인 사용자 이름 또는 이메일 주소를 대량으로 발견하려는 시도를 완화합니다. |
| 알림 이메일                  | 사용자당 프로젝트 또는 그룹당 24시간당 1,000개의 알림 | 프로젝트 또는 그룹과 관련된 알림 이메일에 적용됩니다. [GitLab 17.2](https://gitlab.com/gitlab-org/gitlab/-/issues/439101)에서 일반적으로 사용할 수 있습니다. |
| 오프라인 전송 내보내기 및 가져오기 | 사용자당 분당 6개 요청                                 | [오프라인 전송](../user/import/gitlab_instances/offline-transfer-migrations.md) 내보내기 및 가져오기에 적용되며, 이들은 별도로 제한됩니다. GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/209344)되었습니다. |
| 프로젝트 삭제                     | 인증된 사용자당 분당 60개 요청                  | [프로젝트 삭제](../api/projects.md#delete-a-project)에 `DELETE /projects/:id`을(를) 통해 적용됩니다. `permanently_remove`을(를) 사용하는 요청은 삭제를 즉시 시작하기 때문에 분당 10개 요청으로 별도로 제한됩니다. [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/263603)에서 도입되었으며 [기능 플래그](../administration/feature_flags/_index.md) `group_and_project_delete_rate_limit`이(가) 이름이 지어집니다. 기본적으로 비활성화되었습니다. |
| 리포지토리 아카이브                  | 사용자당 분당 5개 요청                                 | UI 또는 API를 통해 [리포지토리 아카이브 다운로드](../api/repositories.md#retrieve-file-archive-from-a-repository)에 적용됩니다. 제한은 프로젝트 및 다운로드를 시작하는 사용자에게 적용됩니다. |
| 리포지토리 blob 및 파일 액세스      | 프로젝트당 개체당 분당 5개 호출                      | [리포지토리 blob](../api/repositories.md#retrieve-a-blob-from-a-repository) 및 [리포지토리 파일](../api/repository_files.md#retrieve-a-file-from-a-repository) 엔드포인트에서 10 MB보다 큰 파일에 적용됩니다. GitLab 18.1에서 [도입](https://gitlab.com/gitlab-org/security/gitlab/-/issues/1302)되었습니다. |
| 스니펫 생성                     | 인증된 사용자당 시간당 300개 요청                   | [스니펫 생성](../api/snippets.md#create-a-snippet)에 `POST /snippets`을(를) 통해, [프로젝트 스니펫 생성](../api/project_snippets.md#create-a-snippet)에 `POST /projects/:id/snippets`을(를) 통해, 그리고 GitLab UI에서 사용하는 `createSnippet` GraphQL 뮤테이션에 적용됩니다. 제한은 세 가지 모두 간에 공유됩니다. GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251927)되었습니다. |
| 사용자 이름 업데이트                      | 인증된 사용자당 분당 10개 호출                     | 사용자 이름을 변경할 수 있는 빈도를 제한합니다. 사용 중인 사용자 이름을 대량으로 발견하려는 시도를 완화합니다. |
| 사용자 이름 존재                      | IP 주소당 분당 20개 호출                             | 선택한 사용자 이름이 사용 중인지 확인하는 내부 `/users/:username/exists` 엔드포인트에 적용됩니다. |
| 작업 항목 일괄 업데이트                | 인증된 사용자당 분당 30개 요청                  | UI에서 [이슈 일괄 편집](../user/project/issues/managing_issues.md#bulk-edit-issues) 및 [에픽](../user/group/epics/manage_epics.md#bulk-edit-epics)에, 그리고 `workItemBulkUpdate` GraphQL 뮤테이션에 적용됩니다. 제한은 이들 간에 공유됩니다. [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/263775)에서 도입되었으며 [기능 플래그](../administration/feature_flags/_index.md) `work_item_bulk_update_rate_limit`이(가) 이름이 지어집니다. 기본적으로 활성화되어 있습니다. |
| 작업 항목 삭제                   | 인증된 사용자당 분당 300개 요청                 | `workItemDelete` GraphQL 뮤테이션에 적용됩니다. GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253621)되었습니다. [GitLab 19.5](https://gitlab.com/gitlab-org/gitlab/-/work_items/628006)에서 일반적으로 사용할 수 있습니다. |
| 작업 항목 계층 재정렬          | 인증된 사용자당 분당 120개 요청                 | UI에서 [하위 항목 재정렬](../user/work_items/child_items.md#reorganize-child-items)에, 그리고 `workItemsHierarchyReorder` 및 `epicTreeReorder` GraphQL 뮤테이션에 적용됩니다. 제한은 이들 간에 공유됩니다. [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/263802)에서 도입되었으며 [기능 플래그](../administration/feature_flags/_index.md) `work_item_hierarchy_reorder_rate_limit`이(가) 이름이 지어집니다. 기본적으로 활성화되어 있습니다. |

## 관련 항목 {#related-topics}

- [속도 제한](_index.md)
- [학대 및 실패한 인증 금지](abuse_bans.md)
