---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 웹후크 이벤트
description: "GitLab 웹후크 이벤트 및 페이로드 목록입니다. JSON 예제를 포함합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 페이로드의 타임스탬프 형식이 [변경](https://gitlab.com/gitlab-org/gitlab/-/work_items/622832)되었습니다. `YYYY-MM-DD HH:MM:SS` (시간대: `2016-08-12 15:23:28 UTC`) 형식에서 GitLab 19.0의 밀리초 정밀도와 시간대 지정자를 포함한 ISO 8601 형식(`2016-08-12T15:23:28.000Z`)으로 변경되었습니다.

{{< /history >}}

GitLab을 외부 애플리케이션에 연결하고 웹후크를 사용하여 워크플로우를 자동화합니다. GitLab에서 특정 이벤트가 발생하면 웹후크는 구성된 엔드포인트로 자세한 정보가 포함된 HTTP POST 요청을 보냅니다. 코드 변경, 배포, 댓글 및 기타 활동에 반응하는 자동화된 프로세스를 수동 개입 없이 구축합니다.

이 페이지에는 [프로젝트 웹후크](webhooks.md)와 [그룹 웹후크](webhooks.md#group-webhooks)에 대해 트리거되는 이벤트가 나열되어 있습니다.

시스템 웹후크에 대해 트리거되는 이벤트의 목록은 [시스템 웹후크](../../../administration/system_hooks.md)를 참조하세요.

## 프로젝트 및 그룹 웹후크 모두에 대해 트리거되는 이벤트 {#events-triggered-for-both-project-and-group-webhooks}

| 이벤트 유형                                                                    | 트리거 |
|-------------------------------------------------------------------------------|---------|
| [댓글 이벤트](#comment-events)                                              | 커밋, 병합 요청, 이슈 및 코드 스니펫에 새 댓글이 작성되거나 편집됩니다. |
| [배포 이벤트](#deployment-events)                                        | 배포가 시작되고, 완료되고, 실패하고, 취소되고, 승인을 기다리거나 수동 작업을 기다립니다. Premium 및 Ultimate에서는 배포가 승인되거나 거부될 때도 해당됩니다. |
| [이모지 이벤트](#emoji-events)                                                  | 이모지 반응이 추가되거나 제거됩니다. |
| [기능 플래그 이벤트](#feature-flag-events)                                    | 기능 플래그이 켜지거나 꺼집니다. |
| [GitLab Duo 플로우 이벤트](#gitlab-duo-flow-events)                              | 웹후크를 참조하는 GitLab Duo 플로우가 시작되고, 완료되거나 실패합니다. |
| [작업 이벤트](#job-events)                                                      | 작업 상태가 변경됩니다. |
| [병합 요청 이벤트](#merge-request-events)                                  | 병합 요청이 생성되고, 편집되고, 병합되거나 닫히거나, 소스 브랜치에 커밋이 추가됩니다. |
| [마일스톤 이벤트](#milestone-events)                                          | 마일스톤이 생성되고, 닫히고, 다시 열리거나 삭제됩니다. |
| [파이프라인 이벤트](#pipeline-events)                                            | 파이프라인 상태가 변경됩니다. |
| [프로젝트 또는 그룹 액세스 토큰 이벤트](#project-and-group-access-token-events) | 프로젝트 또는 그룹 액세스 토큰이 7, 30 또는 60일 내에 만료될 예정입니다. |
| [푸시 이벤트](#push-events)                                                    | 리포지토리에 푸시가 수행됩니다. |
| [릴리스 이벤트](#release-events)                                              | 릴리스가 생성되고, 편집되거나 삭제됩니다. |
| [태그 이벤트](#tag-events)                                                      | 태그가 리포지토리에서 생성되거나 삭제됩니다. |
| [취약성 이벤트](#vulnerability-events)                                  | 취약성이 생성되거나 업데이트됩니다. |
| [위키 페이지 이벤트](#wiki-page-events)                                          | 위키 페이지가 생성되고, 편집되거나 삭제됩니다. |
| [작업 항목 이벤트](#work-item-events)                                          | 새 작업 항목이 생성되거나 기존 작업 항목이 편집되고, 닫히거나 다시 열립니다. |

## 그룹 웹후크에만 대해 트리거되는 이벤트 {#events-triggered-for-group-webhooks-only}

| 이벤트 유형                                 | 트리거 |
|--------------------------------------------|---------|
| [그룹 구성원 이벤트](#group-member-events) | 사용자가 그룹에 추가되거나 제거되거나 사용자의 액세스 수준 또는 액세스 만료 날짜가 변경됩니다. |
| [프로젝트 이벤트](#project-events)           | 프로젝트가 그룹에서 생성되거나 삭제됩니다. |
| [서브그룹 이벤트](#subgroup-events)         | 서브그룹이 그룹에서 생성되거나 제거됩니다. |

> [!note]
> 작성자의 [GitLab 프로필](https://gitlab.com/-/user_settings/profile)에 공개 이메일이 없으면 웹후크 페이로드의 `email` 특성이 `[REDACTED]` 값을 표시합니다.

## 푸시 이벤트 {#push-events}

푸시 이벤트는 리포지토리에 푸시할 때 트리거되지만 다음 경우는 제외됩니다:

- 태그를 푸시합니다.
- 단일 푸시에 기본적으로 3개 이상의 브랜치 변경이 포함됩니다([`push_event_hooks_limit` 설정](../../../api/settings.md#available-settings)에 따라 다름).

한 번에 20개 이상의 커밋을 푸시하면 페이로드의 `commits` 특성에는 가장 최근의 20개 커밋에 대한 정보만 포함됩니다. 상세한 커밋 데이터를 로드하는 것이 비용이 많이 들기 때문에 이러한 제한이 성능상 이유로 존재합니다. `total_commits_count` 특성에 실제 커밋 수가 포함됩니다.

> [!note]
> 별도의 설정인 `push_event_activities_limit`은 GitLab이 개별 푸시 이벤트를 생성하는지 또는 활동 피드에서 대량 푸시 이벤트를 생성하는지를 제어합니다. 자세한 정보는 [푸시 이벤트 활동 제한](../../../administration/settings/push_event_activities_limit.md)을 참조하세요.

새 커밋 없이 브랜치를 생성하고 푸시하면 페이로드의 `commits` 특성이 비어 있습니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Push Hook
```

페이로드 예제:

```json
{
  "object_kind": "push",
  "event_name": "push",
  "before": "95790bf891e76fee5e1747ab589903a6a1f80f22",
  "after": "da1560886d4f094c3e6c9ef40349f7d38b5d27d7",
  "ref": "refs/heads/master",
  "ref_protected": true,
  "checkout_sha": "da1560886d4f094c3e6c9ef40349f7d38b5d27d7",
  "message": "Hello World",
  "user_id": 4,
  "user_name": "John Smith",
  "user_username": "jsmith",
  "user_email": "john@example.com",
  "user_avatar": "https://s.gravatar.com/avatar/d4c74594d841139328695756648b6bd6?s=8://s.gravatar.com/avatar/d4c74594d841139328695756648b6bd6?s=80",
  "project_id": 15,
  "project": {
    "id": 15,
    "name": "Diaspora",
    "description": "",
    "web_url": "http://example.com/mike/diaspora",
    "avatar_url": null,
    "git_ssh_url": "git@example.com:mike/diaspora.git",
    "git_http_url": "http://example.com/mike/diaspora.git",
    "namespace": "Mike",
    "visibility_level": 0,
    "path_with_namespace": "mike/diaspora",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "http://example.com/mike/diaspora",
    "url": "git@example.com:mike/diaspora.git",
    "ssh_url": "git@example.com:mike/diaspora.git",
    "http_url": "http://example.com/mike/diaspora.git"
  },
  "commits": [
    {
      "id": "b6568db1bc1dcd7f8b4d5a946b0b91f9dacd7327",
      "message": "Update Catalan translation to e38cb41.\n\nSee https://gitlab.com/gitlab-org/gitlab for more information",
      "title": "Update Catalan translation to e38cb41.",
      "timestamp": "2011-12-12T14:27:31+02:00",
      "url": "http://example.com/mike/diaspora/commit/b6568db1bc1dcd7f8b4d5a946b0b91f9dacd7327",
      "author": {
        "name": "Jordi Mallach",
        "email": "jordi@softcatala.org"
      },
      "added": ["CHANGELOG"],
      "modified": ["app/controller/application.rb"],
      "removed": []
    },
    {
      "id": "da1560886d4f094c3e6c9ef40349f7d38b5d27d7",
      "message": "fixed readme",
      "title": "fixed readme",
      "timestamp": "2012-01-03T23:36:29+02:00",
      "url": "http://example.com/mike/diaspora/commit/da1560886d4f094c3e6c9ef40349f7d38b5d27d7",
      "author": {
        "name": "GitLab dev user",
        "email": "gitlabdev@dv6700.(none)"
      },
      "added": ["CHANGELOG"],
      "modified": ["app/controller/application.rb"],
      "removed": []
    }
  ],
  "total_commits_count": 4,
  "push_options": {},
  "repository": {
    "name": "Diaspora",
    "url": "git@example.com:mike/diaspora.git",
    "description": "",
    "homepage": "http://example.com/mike/diaspora",
    "git_http_url": "http://example.com/mike/diaspora.git",
    "git_ssh_url": "git@example.com:mike/diaspora.git",
    "visibility_level": 0
  }
}
```

## 태그 이벤트 {#tag-events}

태그 이벤트는 리포지토리에서 태그를 생성하거나 삭제할 때 트리거됩니다.

단일 푸시에 기본적으로 3개 이상의 태그 변경이 포함되면 이 후크가 실행되지 않습니다. 이 제한은 `push_event_hooks_limit` 설정(기본값: `3`)에 의해 제어되며 태그와 브랜치 모두에 적용됩니다. 초과되면 해당 푸시 이벤트에 대해 웹후크가 전혀 트리거되지 않습니다.

GitLab Self-Managed 인스턴스의 경우 관리자가 [애플리케이션 설정 API](../../../api/settings.md#available-settings)를 사용하여 이 제한을 수정할 수 있습니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Tag Push Hook
```

페이로드 예제:

```json
{
  "object_kind": "tag_push",
  "event_name": "tag_push",
  "before": "0000000000000000000000000000000000000000",
  "after": "82b3d5ae55f7080f1e6022629cdb57bfae7cccc7",
  "ref": "refs/tags/v1.0.0",
  "ref_protected": true,
  "checkout_sha": "82b3d5ae55f7080f1e6022629cdb57bfae7cccc7",
  "message": "Tag message",
  "user_id": 1,
  "user_name": "John Smith",
  "user_username": "jsmith",
  "user_email": "john@example.com",
  "user_avatar": "https://s.gravatar.com/avatar/d4c74594d841139328695756648b6bd6?s=8://s.gravatar.com/avatar/d4c74594d841139328695756648b6bd6?s=80",
  "project_id": 1,
  "project": {
    "id": 1,
    "name": "Example",
    "description": "",
    "web_url": "http://example.com/jsmith/example",
    "avatar_url": null,
    "git_ssh_url": "git@example.com:jsmith/example.git",
    "git_http_url": "http://example.com/jsmith/example.git",
    "namespace": "Jsmith",
    "visibility_level": 0,
    "path_with_namespace": "jsmith/example",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "http://example.com/jsmith/example",
    "url": "git@example.com:jsmith/example.git",
    "ssh_url": "git@example.com:jsmith/example.git",
    "http_url": "http://example.com/jsmith/example.git"
  },
  "commits": [],
  "total_commits_count": 0,
  "push_options": {},
  "repository": {
    "name": "Example",
    "url": "ssh://git@example.com/jsmith/example.git",
    "description": "",
    "homepage": "http://example.com/jsmith/example",
    "git_http_url": "http://example.com/jsmith/example.git",
    "git_ssh_url": "git@example.com:jsmith/example.git",
    "visibility_level": 0
  }
}
```

## 작업 항목 이벤트 {#work-item-events}

{{< history >}}

- `type` 특성이 `object_attributes`에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/467415)되었습니다(GitLab 17.2).
- 에픽 지원이 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/13056)되었습니다(GitLab 17.3). [에픽의 새로운 모양](../../group/epics/_index.md#epics-as-work-items)을 활성화해야 합니다.
- 에픽 지원이 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/468310)되었습니다(GitLab 18.1).
- `start_date` 필드가 `object_attributes`에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/238048)되었습니다(GitLab 19.1).

{{< /history >}}

작업 항목 이벤트는 작업 항목이 생성되고, 편집되고, 닫히거나 다시 열릴 때 트리거됩니다. 지원되는 작업 항목 유형은 다음과 같습니다:

- [에픽](../../group/epics/_index.md)
- [이슈](../issues/_index.md)
- [태스크](../../tasks.md)
- [인시던트](../../../operations/incident_management/incidents.md)
- [테스트 케이스](../../../ci/test_cases/_index.md)
- [요구 사항](../requirements/_index.md)
- [OKR(목표 및 핵심 결과)](../../okrs.md)

이슈 및 [Service Desk](../service_desk/_index.md) 이슈의 경우 `object_kind`는 `issue`이고 `type`는 `Issue`입니다. 다른 모든 작업 항목의 경우 `object_kind` 필드는 `work_item`이고 `type`는 작업 항목 유형입니다.

작업 항목 유형 `Epic`의 경우 변경 사항에 대한 이벤트를 얻으려면 웹후크를 그룹에 등록해야 합니다.

페이로드의 `object_attributes.action` 사용 가능한 값은 다음과 같습니다:

- `open`
- `close`
- `reopen`
- `update`

`assignee` 및 `assignee_id` 키는 더 이상 사용되지 않으며 첫 번째 담당자만 포함합니다.

`escalation_status` 및 `escalation_policy` 필드는 [에스컬레이션을 지원](../../../operations/incident_management/paging.md#paging)하는 이슈 유형(예: 인시던트)에만 사용 가능합니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Issue Hook
```

페이로드 예제:

```json
{
  "object_kind": "issue",
  "event_type": "issue",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project": {
    "id": 1,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlabhq/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "git_http_url":"http://example.com/gitlabhq/gitlab-test.git",
    "namespace":"GitlabHQ",
    "visibility_level":20,
    "path_with_namespace":"gitlabhq/gitlab-test",
    "default_branch":"master",
    "ci_config_path": null,
    "homepage":"http://example.com/gitlabhq/gitlab-test",
    "url":"http://example.com/gitlabhq/gitlab-test.git",
    "ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "http_url":"http://example.com/gitlabhq/gitlab-test.git"
  },
  "object_attributes": {
    "id": 301,
    "title": "New API: create/update/delete file",
    "assignee_ids": [51],
    "assignee_id": 51,
    "author_id": 51,
    "project_id": 14,
    "created_at": "2013-12-03T17:15:43.000Z",
    "updated_at": "2013-12-03T17:15:43.000Z",
    "updated_by_id": 1,
    "last_edited_at": null,
    "last_edited_by_id": null,
    "relative_position": 0,
    "description": "Create new API for manipulations with repository",
    "milestone_id": null,
    "state_id": 1,
    "confidential": false,
    "discussion_locked": true,
    "due_date": null,
    "start_date": null,
    "moved_to_id": null,
    "duplicated_to_id": null,
    "time_estimate": 0,
    "total_time_spent": 0,
    "time_change": 0,
    "human_total_time_spent": null,
    "human_time_estimate": null,
    "human_time_change": null,
    "weight": null,
    "health_status": "at_risk",
    "type": "Issue",
    "iid": 23,
    "url": "http://example.com/diaspora/issues/23",
    "state": "opened",
    "action": "open",
    "severity": "high",
    "escalation_status": "triggered",
    "escalation_policy": {
      "id": 18,
      "name": "Engineering On-call"
    },
    "labels": [{
        "id": 206,
        "title": "API",
        "color": "#ffffff",
        "project_id": 14,
        "created_at": "2013-12-03T17:15:43.000Z",
        "updated_at": "2013-12-03T17:15:43.000Z",
        "template": false,
        "description": "API related issues",
        "type": "ProjectLabel",
        "group_id": 41
      }]
  },
  "repository": {
    "name": "Gitlab Test",
    "url": "http://example.com/gitlabhq/gitlab-test.git",
    "description": "Aut reprehenderit ut est.",
    "homepage": "http://example.com/gitlabhq/gitlab-test"
  },
  "assignees": [{
    "name": "User1",
    "username": "user1",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon"
  }],
  "assignee": {
    "name": "User1",
    "username": "user1",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon"
  },
  "labels": [{
    "id": 206,
    "title": "API",
    "color": "#ffffff",
    "project_id": 14,
    "created_at": "2013-12-03T17:15:43.000Z",
    "updated_at": "2013-12-03T17:15:43.000Z",
    "template": false,
    "description": "API related issues",
    "type": "ProjectLabel",
    "group_id": 41
  }],
  "changes": {
    "updated_by_id": {
      "previous": null,
      "current": 1
    },
    "updated_at": {
      "previous": "2017-09-15T16:50:55.000Z",
      "current": "2017-09-15T16:52:00.000Z"
    },
    "labels": {
      "previous": [{
        "id": 206,
        "title": "API",
        "color": "#ffffff",
        "project_id": 14,
        "created_at": "2013-12-03T17:15:43.000Z",
        "updated_at": "2013-12-03T17:15:43.000Z",
        "template": false,
        "description": "API related issues",
        "type": "ProjectLabel",
        "group_id": 41
      }],
      "current": [{
        "id": 205,
        "title": "Platform",
        "color": "#123123",
        "project_id": 14,
        "created_at": "2013-12-03T17:15:43.000Z",
        "updated_at": "2013-12-03T17:15:43.000Z",
        "template": false,
        "description": "Platform related issues",
        "type": "ProjectLabel",
        "group_id": 41
      }]
    }
  }
}
```

## 댓글 이벤트 {#comment-events}

댓글 이벤트는 커밋, 병합 요청, 이슈 및 코드 스니펫에 새 댓글이 작성되거나 편집될 때 트리거됩니다.

노트 데이터는 `object_attributes`에 저장됩니다(예: `note` 또는 `noteable_type`). 페이로드에는 댓글의 대상에 대한 정보가 포함됩니다. 예를 들어 이슈에 대한 댓글은 `issue` 키 아래에 특정 이슈 정보를 포함합니다.

사용 가능한 대상 유형은 다음과 같습니다:

- `commit`
- `merge_request`
- `issue`
- `snippet`

페이로드의 `object_attributes.action` 사용 가능한 값은 다음과 같습니다:

- `create`
- `update`

### 커밋에 대한 댓글 {#comment-on-a-commit}

요청 헤더:

```plaintext
X-Gitlab-Event: Note Hook
```

페이로드 예제:

```json
{
  "object_kind": "note",
  "event_type": "note",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project_id": 5,
  "project":{
    "id": 5,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlabhq/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "git_http_url":"http://example.com/gitlabhq/gitlab-test.git",
    "namespace":"GitlabHQ",
    "visibility_level":20,
    "path_with_namespace":"gitlabhq/gitlab-test",
    "default_branch":"master",
    "homepage":"http://example.com/gitlabhq/gitlab-test",
    "url":"http://example.com/gitlabhq/gitlab-test.git",
    "ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "http_url":"http://example.com/gitlabhq/gitlab-test.git"
  },
  "repository":{
    "name": "Gitlab Test",
    "url": "http://example.com/gitlab-org/gitlab-test.git",
    "description": "Aut reprehenderit ut est.",
    "homepage": "http://example.com/gitlab-org/gitlab-test"
  },
  "object_attributes": {
    "id": 1243,
    "internal": false,
    "note": "This is a commit comment. How does this work?",
    "noteable_type": "Commit",
    "author_id": 1,
    "created_at": "2015-05-17T18:08:09.000Z",
    "updated_at": "2015-05-17T18:08:09.000Z",
    "project_id": 5,
    "attachment":null,
    "line_code": "bec9703f7a456cd2b4ab5fb3220ae016e3e394e3_0_1",
    "commit_id": "cfe32cf61b73a0d5e9f13e774abde7ff789b1660",
    "noteable_id": null,
    "system": false,
    "st_diff": {
      "diff": "--- /dev/null\n+++ b/six\n@@ -0,0 +1 @@\n+Subproject commit 409f37c4f05865e4fb208c771485f211a22c4c2d\n",
      "new_path": "six",
      "old_path": "six",
      "a_mode": "0",
      "b_mode": "160000",
      "new_file": true,
      "renamed_file": false,
      "deleted_file": false
    },
    "action": "create",
    "url": "http://example.com/gitlab-org/gitlab-test/commit/cfe32cf61b73a0d5e9f13e774abde7ff789b1660#note_1243"
  },
  "commit": {
    "id": "cfe32cf61b73a0d5e9f13e774abde7ff789b1660",
    "message": "Add submodule\n\nSigned-off-by: Example User \u003cuser@example.com.com\u003e\n",
    "timestamp": "2014-02-27T10:06:20+02:00",
    "url": "http://example.com/gitlab-org/gitlab-test/commit/cfe32cf61b73a0d5e9f13e774abde7ff789b1660",
    "author": {
      "name": "Example User",
      "email": "user@example.com"
    }
  }
}
```

### 병합 요청에 대한 댓글 {#comment-on-a-merge-request}

요청 헤더:

```plaintext
X-Gitlab-Event: Note Hook
```

페이로드 예제:

```json
{
  "object_kind": "note",
  "event_type": "note",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project_id": 5,
  "project":{
    "id": 5,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlab-org/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "git_http_url":"http://example.com/gitlab-org/gitlab-test.git",
    "namespace":"Gitlab Org",
    "visibility_level":10,
    "path_with_namespace":"gitlab-org/gitlab-test",
    "default_branch":"master",
    "homepage":"http://example.com/gitlab-org/gitlab-test",
    "url":"http://example.com/gitlab-org/gitlab-test.git",
    "ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "http_url":"http://example.com/gitlab-org/gitlab-test.git"
  },
  "repository":{
    "name": "Gitlab Test",
    "url": "http://localhost/gitlab-org/gitlab-test.git",
    "description": "Aut reprehenderit ut est.",
    "homepage": "http://example.com/gitlab-org/gitlab-test"
  },
  "object_attributes": {
    "id": 1244,
    "internal": false,
    "note": "This MR needs work.",
    "noteable_type": "MergeRequest",
    "author_id": 1,
    "created_at": "2015-05-17T18:21:36.000Z",
    "updated_at": "2015-05-17T18:21:36.000Z",
    "project_id": 5,
    "attachment": null,
    "line_code": null,
    "commit_id": "",
    "noteable_id": 7,
    "system": false,
    "st_diff": null,
    "action": "create",
    "url": "http://example.com/gitlab-org/gitlab-test/merge_requests/1#note_1244"
  },
  "merge_request": {
    "id": 7,
    "target_branch": "markdown",
    "source_branch": "master",
    "source_project_id": 5,
    "author_id": 8,
    "assignee_id": 28,
    "title": "Tempora et eos debitis quae laborum et.",
    "created_at": "2015-03-01T20:12:53.000Z",
    "updated_at": "2015-03-21T18:27:27.000Z",
    "milestone_id": 11,
    "state": "opened",
    "merge_status": "cannot_be_merged",
    "target_project_id": 5,
    "iid": 1,
    "description": "Et voluptas corrupti assumenda temporibus. Architecto cum animi eveniet amet asperiores. Vitae numquam voluptate est natus sit et ad id.",
    "position": 0,
    "labels": [
      {
        "id": 25,
        "title": "Afterpod",
        "color": "#3e8068",
        "project_id": null,
        "created_at": "2019-06-05T14:32:20.211Z",
        "updated_at": "2019-06-05T14:32:20.211Z",
        "template": false,
        "description": null,
        "type": "GroupLabel",
        "group_id": 4
      },
      {
        "id": 86,
        "title": "Element",
        "color": "#231afe",
        "project_id": 4,
        "created_at": "2019-06-05T14:32:20.637Z",
        "updated_at": "2019-06-05T14:32:20.637Z",
        "template": false,
        "description": null,
        "type": "ProjectLabel",
        "group_id": null
      }
    ],
    "source":{
      "name":"Gitlab Test",
      "description":"Aut reprehenderit ut est.",
      "web_url":"http://example.com/gitlab-org/gitlab-test",
      "avatar_url":null,
      "git_ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
      "git_http_url":"http://example.com/gitlab-org/gitlab-test.git",
      "namespace":"Gitlab Org",
      "visibility_level":10,
      "path_with_namespace":"gitlab-org/gitlab-test",
      "default_branch":"master",
      "homepage":"http://example.com/gitlab-org/gitlab-test",
      "url":"http://example.com/gitlab-org/gitlab-test.git",
      "ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
      "http_url":"http://example.com/gitlab-org/gitlab-test.git"
    },
    "target": {
      "name":"Gitlab Test",
      "description":"Aut reprehenderit ut est.",
      "web_url":"http://example.com/gitlab-org/gitlab-test",
      "avatar_url":null,
      "git_ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
      "git_http_url":"http://example.com/gitlab-org/gitlab-test.git",
      "namespace":"Gitlab Org",
      "visibility_level":10,
      "path_with_namespace":"gitlab-org/gitlab-test",
      "default_branch":"master",
      "homepage":"http://example.com/gitlab-org/gitlab-test",
      "url":"http://example.com/gitlab-org/gitlab-test.git",
      "ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
      "http_url":"http://example.com/gitlab-org/gitlab-test.git"
    },
    "last_commit": {
      "id": "562e173be03b8ff2efb05345d12df18815438a4b",
      "message": "Merge branch 'another-branch' into 'master'\n\nCheck in this test\n",
      "timestamp": "2015-04-08T21:00:25-07:00",
      "url": "http://example.com/gitlab-org/gitlab-test/commit/562e173be03b8ff2efb05345d12df18815438a4b",
      "author": {
        "name": "John Smith",
        "email": "john@example.com"
      }
    },
    "work_in_progress": false,
    "draft": false,
    "assignee": {
      "name": "User1",
      "username": "user1",
      "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon"
    },
    "detailed_merge_status": "checking"
  }
}
```

### 이슈에 대한 댓글 {#comment-on-an-issue}

- `assignee_id` 필드는 더 이상 사용되지 않으며 첫 번째 담당자만 표시합니다.
- `event_type`은(는) 기밀 이슈의 경우 `confidential_note`로 설정됩니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Note Hook
```

페이로드 예제:

```json
{
  "object_kind": "note",
  "event_type": "note",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project_id": 5,
  "project":{
    "id": 5,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlab-org/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "git_http_url":"http://example.com/gitlab-org/gitlab-test.git",
    "namespace":"Gitlab Org",
    "visibility_level":10,
    "path_with_namespace":"gitlab-org/gitlab-test",
    "default_branch":"master",
    "homepage":"http://example.com/gitlab-org/gitlab-test",
    "url":"http://example.com/gitlab-org/gitlab-test.git",
    "ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "http_url":"http://example.com/gitlab-org/gitlab-test.git"
  },
  "repository":{
    "name":"diaspora",
    "url":"git@example.com:mike/diaspora.git",
    "description":"",
    "homepage":"http://example.com/mike/diaspora"
  },
  "object_attributes": {
    "id": 1241,
    "internal": false,
    "note": "Hello world",
    "noteable_type": "Issue",
    "author_id": 1,
    "created_at": "2015-05-17T17:06:40.000Z",
    "updated_at": "2015-05-17T17:06:40.000Z",
    "project_id": 5,
    "attachment": null,
    "line_code": null,
    "commit_id": "",
    "noteable_id": 92,
    "system": false,
    "st_diff": null,
    "action": "create",
    "url": "http://example.com/gitlab-org/gitlab-test/issues/17#note_1241"
  },
  "issue": {
    "id": 92,
    "title": "test",
    "assignee_ids": [],
    "assignee_id": null,
    "author_id": 1,
    "project_id": 5,
    "created_at": "2015-04-12T14:53:17.000Z",
    "updated_at": "2015-04-26T08:28:42.000Z",
    "position": 0,
    "branch_name": null,
    "description": "test",
    "milestone_id": null,
    "state": "closed",
    "iid": 17,
    "labels": [
      {
        "id": 25,
        "title": "Afterpod",
        "color": "#3e8068",
        "project_id": null,
        "created_at": "2019-06-05T14:32:20.211Z",
        "updated_at": "2019-06-05T14:32:20.211Z",
        "template": false,
        "description": null,
        "type": "GroupLabel",
        "group_id": 4
      },
      {
        "id": 86,
        "title": "Element",
        "color": "#231afe",
        "project_id": 4,
        "created_at": "2019-06-05T14:32:20.637Z",
        "updated_at": "2019-06-05T14:32:20.637Z",
        "template": false,
        "description": null,
        "type": "ProjectLabel",
        "group_id": null
      }
    ]
  }
}
```

### 코드 스니펫에 대한 댓글 {#comment-on-a-code-snippet}

요청 헤더:

```plaintext
X-Gitlab-Event: Note Hook
```

페이로드 예제:

```json
{
  "object_kind": "note",
  "event_type": "note",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=40\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project_id": 5,
  "project":{
    "id": 5,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlab-org/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "git_http_url":"http://example.com/gitlab-org/gitlab-test.git",
    "namespace":"Gitlab Org",
    "visibility_level":10,
    "path_with_namespace":"gitlab-org/gitlab-test",
    "default_branch":"master",
    "homepage":"http://example.com/gitlab-org/gitlab-test",
    "url":"http://example.com/gitlab-org/gitlab-test.git",
    "ssh_url":"git@example.com:gitlab-org/gitlab-test.git",
    "http_url":"http://example.com/gitlab-org/gitlab-test.git"
  },
  "repository":{
    "name":"Gitlab Test",
    "url":"http://example.com/gitlab-org/gitlab-test.git",
    "description":"Aut reprehenderit ut est.",
    "homepage":"http://example.com/gitlab-org/gitlab-test"
  },
  "object_attributes": {
    "id": 1245,
    "internal": false,
    "note": "Is this snippet doing what it's supposed to be doing?",
    "noteable_type": "Snippet",
    "author_id": 1,
    "created_at": "2015-05-17T18:35:50.000Z",
    "updated_at": "2015-05-17T18:35:50.000Z",
    "project_id": 5,
    "attachment": null,
    "line_code": null,
    "commit_id": "",
    "noteable_id": 53,
    "system": false,
    "st_diff": null,
    "action": "create",
    "url": "http://example.com/gitlab-org/gitlab-test/-/snippets/53#note_1245"
  },
  "snippet": {
    "id": 53,
    "title": "test",
    "description": "A snippet description.",
    "content": "puts 'Hello world'",
    "author_id": 1,
    "project_id": 5,
    "created_at": "2015-04-09T02:40:38.000Z",
    "updated_at": "2015-04-09T02:40:38.000Z",
    "file_name": "test.rb",
    "type": "ProjectSnippet",
    "visibility_level": 0,
    "url": "http://example.com/gitlab-org/gitlab-test/-/snippets/53"
  }
}
```

## 병합 요청 이벤트 {#merge-request-events}

{{< history >}}

- 자동 병합 설정 또는 취소 시 웹후크 이벤트가 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/515530)되었습니다(GitLab 19.2).

{{< /history >}}

병합 요청 이벤트는 다음 경우에 트리거됩니다:

- 새 병합 요청이 생성됩니다.
- 기존 병합 요청이 업데이트되고, 승인되고(모든 필수 승인자에 의해), 승인 취소되거나, 병합되거나 닫힙니다.
- 개별 사용자가 기존 병합 요청에 대한 승인을 추가하거나 제거합니다.
- 검토자가 병합 요청을 검토하도록 재요청됩니다.
- 병합 요청이 자동 병합으로 설정되거나 자동 병합이 취소됩니다.
- 커밋이 소스 브랜치에 추가됩니다.
- 병합 요청에서 모든 스레드가 해결됩니다.

병합 요청 이벤트는 `changes` 필드가 비어 있는 경우에도 트리거될 수 있습니다. 웹후크 수신자는 항상 병합 요청의 실제 변경 사항에 대해 `changes` 필드의 내용을 검사해야 합니다.

### 페이로드 구조 {#payload-structure}

웹후크 페이로드의 JSON 구조는 모든 작업 유형에서 일관성이 있습니다. 차이점은 데이터를 포함하는 필드와 `oldrev`, `system` 및 `system_action`와 같은 조건부 필드의 존재 여부에 있습니다.

페이로드의 `object_attributes.action` 사용 가능한 값은 다음과 같습니다:

- `open`: 새 병합 요청이 생성됩니다.
- `close`: 병합 요청이 닫혔습니다.
- `reopen`: 닫힌 병합 요청이 다시 열립니다.
- `update`: 병합 요청이 업데이트됩니다. 여기에는 일반 업데이트, 검토 재요청 작업 및 자동 병합 설정 또는 취소가 포함됩니다. `changes` 필드를 확인하여 특정 업데이트 유형을 결정합니다. 자동 병합이 설정되거나 취소되면 `changes` 필드는 병합 요청의 자동 병합 상태 변경을 반영합니다.
- `approval`: 사용자가 자신의 승인을 추가합니다.
- `approved`: 병합 요청이 모든 필수 승인자에 의해 완전히 승인됩니다.
- `unapproval`: 사용자가 수동으로 또는 시스템에서 자신의 승인을 제거합니다.
- `unapproved`: 이전에 승인된 병합 요청이 수동으로 또는 시스템에서 승인된 상태를 잃습니다.
- `merge`: 병합 요청이 병합됩니다.

병합 요청 웹후크 페이로드에 다음 최상위 필드가 포함됩니다:

| 필드               | 형식   | 설명 |
|---------------------|--------|-------------|
| `object_kind`       | 문자열 | `"merge_request"` |
| `event_type`        | 문자열 | `"merge_request"` |
| `user`              | 객체 | 이벤트를 트리거한 사용자입니다. |
| `project`           | 객체 | 대상 프로젝트입니다. |
| `object_attributes` | 객체 | 병합 요청 데이터입니다. |
| `changes`           | 객체 | 작업 중에 변경된 특성을 포함합니다. |
| `assignees`         | 배열  | 현재 할당된 사용자입니다. |
| `reviewers`         | 배열  | 현재 할당된 검토자입니다. |
| `labels`            | 배열  | 레이블 객체입니다. |
| `repository`        | 객체 | 지원 중단됨. 대신 `project`을 사용합니다. 리포지토리 정보입니다. |

### 더 이상 사용되지 않는 필드 {#deprecated-fields}

다음 필드는 더 이상 사용되지 않으며 하위 호환성을 위해서만 포함됩니다. 권장 대체 항목을 대신 사용하세요:

| 더 이상 사용되지 않는 필드                     | 권장 대체 항목 |
|--------------------------------------|-------------------------|
| `object_attributes.assignee_id`      | `object_attributes.assignee_ids` |
| `object_attributes.work_in_progress` | `object_attributes.draft` |
| `project.http_url`                   | `project.git_http_url`  |
| `project.homepage`                   | `project.web_url`       |
| `project.ssh_url`                    | `project.git_ssh_url`   |
| `project.url`                        | `project.git_ssh_url` 또는 `project.git_http_url` |
| `repository`                         | `project`               |

### `object_attributes` 필드 {#object_attributes-field}

{{< history >}}

- `actioned_at` [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224849)되었습니다(GitLab 18.10).
- `merged_at` [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/235360)되었습니다(GitLab 19.1).
- `target_branch_protected` [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/480576)되었습니다(GitLab 19.2).

{{< /history >}}

`object_attributes` 필드에 병합 요청의 현재 상태가 포함됩니다. 다음 필드를 포함합니다:

| 필드                           | 형식    | 설명 |
|---------------------------------|---------|-------------|
| `action`                        | 문자열  | 웹후크를 트리거한 작업입니다. 예를 들어 `open`, `update` 또는 `merge`입니다. |
| `actioned_at`                   | 문자열  | 웹후크를 트리거한 작업이 발생한 시간입니다. |
| `approval_rules`                | 배열   | 승인 규칙 객체 배열(EE만 해당). |
| `assignee_ids`                  | 배열   | 담당자 ID 배열입니다. |
| `author_id`                     | 정수 | 병합 요청 작성자의 ID입니다. |
| `blocking_discussions_resolved` | 부울 | 차단 토론이 해결되었는지 여부입니다. |
| `created_at`                    | 문자열  | 병합 요청이 생성되었을 때입니다. |
| `description`                   | 문자열  | 병합 요청 설명입니다. |
| `detailed_merge_status`         | 문자열  | 자세한 병합 상태 정보입니다. 가능한 값의 목록은 [병합 상태](../../../api/merge_requests.md#merge-status)를 참조하세요. |
| `draft`                         | 부울 | 병합 요청이 초안인지 여부입니다. |
| `first_contribution`            | 부울 | 작성자의 첫 기여인지 여부입니다. |
| `head_pipeline_id`              | 정수 | 헤드 파이프라인의 ID입니다. |
| `human_time_change`             | 문자열  | 사람이 읽을 수 있는 시간 변경입니다. |
| `human_time_estimate`           | 문자열  | 사람이 읽을 수 있는 시간 추정치입니다. |
| `human_total_time_spent`        | 문자열  | 사람이 읽을 수 있는 총 시간 소요입니다. |
| `id`                            | 정수 | 병합 요청 ID입니다. |
| `iid`                           | 정수 | 병합 요청의 내부 ID입니다. |
| `labels`                        | 배열   | 레이블 객체 배열입니다. |
| `last_commit`                   | 객체  | 세부 정보가 있는 마지막 커밋 객체입니다. |
| `last_edited_at`                | 문자열  | 병합 요청을 마지막으로 편집했을 때입니다. |
| `last_edited_by_id`             | 정수 | 마지막으로 편집한 사용자의 ID입니다. |
| `merge_commit_sha`              | 문자열  | 병합 커밋의 SHA입니다. |
| `merged_at`                     | 문자열  | 병합 요청이 병합된 시간입니다. 아직 병합되지 않은 경우 `null`입니다. |
| `merge_error`                   | 문자열  | 모든 병합 오류 메시지입니다. |
| `merge_params`                  | 객체  | 매개변수 병합입니다. |
| `merge_status`                  | 문자열  | 병합 요청의 상태입니다. |
| `merge_user_id`                 | 정수 | 병합한 사용자의 ID입니다. |
| `merge_when_pipeline_succeeds`  | 부울 | 자동 병합이 활성화되었는지 여부입니다. |
| `milestone_id`                  | 정수 | 마일스톤의 ID입니다. |
| `oldrev`                        | 문자열  | 이전 커밋 SHA(푸시 관련 이벤트에만 표시). |
| `prepared_at`                   | 문자열  | 병합 요청이 준비된 시간의 타임스탬프입니다. 이 필드는 모든 [준비 단계](../../../api/merge_requests.md#preparation-steps)가 완료된 후에만 한 번 채워지며 변경 사항이 더 추가되면 업데이트되지 않습니다. |
| `reviewer_ids`                  | 배열   | 검토자 ID 배열입니다. |
| `source_branch`                 | 문자열  | 소스 브랜치 이름입니다. |
| `source`                        | 객체  | 소스 프로젝트 세부 정보입니다. 예를 들어 이름 및 설명입니다. |
| `source_project_id`             | 정수 | 소스 프로젝트의 ID입니다. |
| `squash_commit_sha`             | 문자열  | 스쿼시 커밋의 SHA입니다. 병합 요청이 스쿼시로 병합된 경우에만 표시됩니다. |
| `state_id`                      | 정수 | 상태 ID(`1`: 열림, `2`: 닫힘, `3`: 병합됨, `4`: 잠금). |
| `state`                         | 문자열  | 병합 요청의 상태(`opened`, `closed`, `merged`, `locked`). |
| `system_action`                 | 문자열  | 시스템 작업(`system`이 `true`인 경우에만 표시). |
| `system`                        | 부울 | 이벤트가 시스템에서 시작되었는지 여부입니다. |
| `target_branch`                 | 문자열  | 대상 브랜치 이름입니다. |
| `target_branch_protected`       | 부울 | 대상 브랜치가 [보호 브랜치](../repository/branches/protected.md)인지 여부입니다. |
| `target`                        | 객체  | 대상 프로젝트 세부 정보입니다. 예를 들어 이름 및 설명입니다. |
| `target_project_id`             | 정수 | 대상 프로젝트의 ID입니다. |
| `time_change`                   | 정수 | 시간 변경(초)입니다. |
| `time_estimate`                 | 정수 | 시간 추정치(초)입니다. |
| `title`                         | 문자열  | 병합 요청 제목입니다. |
| `total_time_spent`              | 정수 | 총 시간 소요(초)입니다. |
| `updated_at`                    | 문자열  | 병합 요청을 마지막으로 업데이트했을 때입니다. |
| `updated_by_id`                 | 정수 | 마지막으로 업데이트한 사용자의 ID입니다. |
| `url`                           | 문자열  | 병합 요청의 URL입니다. |

### `changes` 필드 {#changes-field}

`changes` 필드에는 작업 중에 수정된 필드만 포함됩니다. `object_attributes`의 모든 필드가 `changes`에 나타나는 것은 아닙니다.

변경된 각 필드는 다음 형식을 따릅니다:

```json
{
  "field_name": {
    "previous": "old_value",
    "current": "new_value"
  }
}
```

#### 특성 {#attributes}

- `assignees`
- `blocking_discussions_resolved`
- `description`
- `draft`
- `head_pipeline_id`
- `labels`
- `last_edited_at`
- `last_edited_by_id`
- `merge_commit_sha`
- `merge_error`
- `merge_params`
- `merge_status`
- `merge_user_id`
- `merge_when_pipeline_succeeds`
- `milestone_id`
- `prepared_at`
- `reviewer_ids`
- `reviewers`
- `squash_commit_sha`
- `state_id`
- `target_branch`
- `time_change`
- `time_estimate`
- `title`
- `total_time_spent`
- `updated_at`
- `updated_by_id`

### 병합 요청 작업 특정 필드 {#merge-request-action-specific-fields}

`object_attributes.oldrev` 필드는 `update` 작업에 대해 다음과 같은 실제 코드 변경 사항이 있을 때만 사용 가능합니다:

- 새 코드가 소스 브랜치에 푸시됩니다.
- [제안](../merge_requests/reviews/suggestions.md)이 적용됩니다.

다음 예제는 `update` 이벤트와 `oldrev`(부분 페이로드)를 보여 줍니다:

```json
{
  "object_kind": "merge_request",
  "event_type": "merge_request",
  "object_attributes": {
    "action": "update",
    "oldrev": "e59094b8de0f2f91abbe4760a52d9137260252d8"
  }
}
```

### 시스템 시작 병합 요청 이벤트 {#system-initiated-merge-request-events}

일부 병합 요청 이벤트는 승인이 새 커밋 푸시로 인해 리셋될 때와 같이 시스템에서 자동으로 트리거됩니다. 이러한 시스템 시작 웹후크 이벤트는 푸시 이벤트에 의해서만 트리거되며 페이로드에 더 많은 필드를 포함합니다:

- `object_attributes.system`: 부울 필드입니다. `true`이면 이벤트가 시스템에서 트리거되었습니다. `false`이면 사용자 작업이 이벤트를 트리거했습니다.
- `object_attributes.system_action`: 문자열 필드로 `system`이 `true`일 때만 표시됩니다. 시스템 작업에 대해 더 많은 컨텍스트를 제공합니다. 사용 가능한 값은 다음과 같습니다:

  - `approvals_reset_on_push`: 프로젝트에서 **푸시할때 승인 재설정**이(가) 활성화되었으며 새 커밋이 푸시되었습니다.
  - `code_owner_approvals_reset_on_push`: 프로젝트에서 **코드 소유자 선택 제거**가 활성화되었으며 코드 소유자 승인이 CODEOWNERS 규칙과 일치하는 파일의 변경 사항으로 인해 리셋되었습니다.
- `object_attributes.action`: 승인 리셋 이벤트의 경우 값은 다음과 같습니다:
  - `unapproved`은(는) 병합 요청이 승인됨에서 미승인으로 변경됩니다.
  - `unapproval`은(는) 전체 승인 상태를 변경하지 않고 승인이 제거됩니다.

다른 승인 리셋 시나리오는 웹후크를 트리거하지 않습니다.

다음 예제는 시스템 시작 이벤트를 보여 줍니다(부분 페이로드):

```json
{
  "object_kind": "merge_request",
  "event_type": "merge_request",
  "object_attributes": {
    "action": "unapproved",
    "system": true,
    "system_action": "approvals_reset_on_push"
  }
}
```

### 검토자 상태 추적 {#reviewer-state-tracking}

병합 요청 웹후크 페이로드의 `reviewers` 배열에는 각 검토자에 대한 `state` 필드가 포함됩니다. `state` 필드는 검토자의 현재 검토 상태를 나타냅니다:

- `unreviewed`: 검토자가 병합 요청을 아직 검토하지 않았습니다.
- `review_started`: 검토자가 검토를 시작했지만 완료하지 않았습니다.
- `reviewed`: 검토자가 검토를 완료했습니다.
- `requested_changes`: 검토자가 변경을 요청했습니다.
- `approved`: 검토자가 병합 요청을 승인했습니다.
- `unapproved`: 검토자가 이전에 승인했지만 승인이 제거되었습니다.

다음 예제는 검토자 배열을 보여 줍니다(부분 페이로드):

```json
{
  "reviewers": [
    {
      "id": 6,
      "name": "User1",
      "username": "user1",
      "state": "unreviewed",
      "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
      "email": "user1@example.com"
    }
  ]
}
```

### 재요청 검토 이벤트 {#re-request-review-events}

검토자가 병합 요청에 대해 재요청될 때 웹후크는 `action: "update"`에서 트리거되며 `changes` 객체에 향상된 정보를 포함합니다. 변경 페이로드에 다음이 포함됩니다:

- **이전 상태**(첫 번째 배열): 재요청 전의 검토자 상태를 표시하고 `re_requested: false`
- **현재 상태**(두 번째 배열): 재요청 후 검토자의 업데이트된 상태를 표시하고 `re_requested: true` 검토자를 다시 요청합니다.
- **상태 전환**: 검토자의 상태가 어떻게 변경되었는지를 보여 줍니다(예를 들어 `approved`에서 `unreviewed`로).

다음 예제는 재요청 검토 변경 사항을 보여 줍니다(부분 페이로드):

```json
{
  "object_kind": "merge_request",
  "event_type": "merge_request",
  "object_attributes": {
    "action": "update"
  },
  "changes": {
    "reviewers": [
      [
        {
          "id": 6,
          "name": "User1",
          "username": "user1",
          "state": "approved",
          "re_requested": false,
          "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
          "email": "user1@example.com"
        }
      ],
      [
        {
          "id": 6,
          "name": "User1",
          "username": "user1",
          "state": "unreviewed",
          "re_requested": true,
          "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
          "email": "user1@example.com"
        }
      ]
    ]
  }
}
```

### 검토 제출 이벤트 {#submit-review-events}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/592358)되었습니다.

{{< /history >}}

검토자가 검토를 제출할 때 GitLab은 `action: "update"`을(를) 통해 웹후크를 트리거하여 검토자의 새로운 상태를 반영합니다. 이는 검토자가 변경을 요청하거나 검토를 검토됨으로 표시하거나 승인하거나 승인을 취소하는 경우에 적용됩니다. `changes` 객체에는 첫 번째 배열의 검토자의 이전 상태와 두 번째 배열의 업데이트된 상태가 포함됩니다. 예를 들어 변경을 요청하는 검토자는 `review_started`에서 `requested_changes`로 전환됩니다.

`re_requested` 필드는 제출된 검토는 재요청이 아니기 때문에 두 배열 모두에서 `false`입니다.

다음 예제는 검토 제출 변경 사항을 보여 줍니다(부분 페이로드):

```json
{
  "object_kind": "merge_request",
  "event_type": "merge_request",
  "object_attributes": {
    "action": "update"
  },
  "changes": {
    "reviewers": [
      [
        {
          "id": 6,
          "name": "User1",
          "username": "user1",
          "state": "review_started",
          "re_requested": false,
          "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
          "email": "user1@example.com"
        }
      ],
      [
        {
          "id": 6,
          "name": "User1",
          "username": "user1",
          "state": "requested_changes",
          "re_requested": false,
          "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
          "email": "user1@example.com"
        }
      ]
    ]
  }
}
```

### 완전한 페이로드 예제 {#complete-payload-example}

요청 헤더:

```plaintext
X-Gitlab-Event: Merge Request Hook
```

다음 예제는 `open` 작업에 대한 완전한 병합 요청 웹후크 페이로드입니다. 더 이상 사용되지 않는 필드는 명확성을 위해 생략됩니다. 더 이상 사용되지 않는 필드 및 권장 대체 항목의 목록은 [더 이상 사용되지 않는 필드](#deprecated-fields)를 참조하세요.

```json
{
  "object_kind": "merge_request",
  "event_type": "merge_request",
  "user": {
    "id": 1,
    "name": "Alex Garcia",
    "username": "agarcia",
    "avatar_url": "https://www.gravatar.com/avatar/1a29da0ccd099482194440fac762f5ccb4ec53227761d1859979367644a889a5?s=80&d=identicon",
    "email": "agarcia@example.com"
  },
  "project": {
    "id": 2,
    "name": "Flight Management",
    "description": "Flight management application for tracking aircraft status.",
    "web_url": "http://gitlab.example.com/flightjs/flight-management",
    "avatar_url": null,
    "git_ssh_url": "ssh://git@gitlab.example.com:flightjs/flight-management.git",
    "git_http_url": "http://gitlab.example.com/flightjs/flight-management.git",
    "namespace": "Flightjs",
    "visibility_level": 0,
    "path_with_namespace": "flightjs/flight-management",
    "default_branch": "main",
    "ci_config_path": null
  },
  "object_attributes": {
    "author_id": 1,
    "created_at": "2026-01-16T05:56:22.000Z",
    "description": "This merge request adds input validation to the booking form.",
    "draft": false,
    "head_pipeline_id": null,
    "id": 93,
    "iid": 16,
    "last_edited_at": null,
    "last_edited_by_id": null,
    "merge_commit_sha": null,
    "merged_at": null,
    "merge_error": null,
    "merge_params": {
      "force_remove_source_branch": "1"
    },
    "merge_status": "checking",
    "merge_user_id": null,
    "merge_when_pipeline_succeeds": false,
    "milestone_id": 8,
    "source_branch": "feature/booking-validation",
    "source_project_id": 2,
    "squash_commit_sha": null,
    "state_id": 1,
    "target_branch": "main",
    "target_branch_protected": true,
    "target_project_id": 2,
    "time_estimate": 0,
    "title": "Add input validation to booking form",
    "updated_at": "2026-01-16T05:56:25.000Z",
    "updated_by_id": null,
    "prepared_at": "2026-01-16T05:56:25.000Z",
    "assignee_ids": [
      1
    ],
    "blocking_discussions_resolved": true,
    "detailed_merge_status": "checking",
    "first_contribution": true,
    "human_time_change": null,
    "human_time_estimate": null,
    "human_total_time_spent": null,
    "labels": [
      {
        "id": 19,
        "title": "enhancement",
        "color": "#adb21a",
        "project_id": null,
        "created_at": "2026-01-07T00:03:52.000Z",
        "updated_at": "2026-01-07T00:03:52.000Z",
        "template": false,
        "description": null,
        "type": "GroupLabel",
        "group_id": 24
      }
    ],
    "last_commit": {
      "id": "e59094b8de0f2f91abbe4760a52d9137260252d8",
      "message": "Add email format validation",
      "title": "Add email format validation",
      "timestamp": "2026-01-16T05:01:10+00:00",
      "url": "http://gitlab.example.com/flightjs/flight-management/-/commit/e59094b8de0f2f91abbe4760a52d9137260252d8",
      "author": {
        "name": "Alex Garcia",
        "email": "agarcia@example.com"
      }
    },
    "reviewer_ids": [
      25
    ],
    "source": {
      "id": 2,
      "name": "Flight Management",
      "description": "Flight management application for tracking aircraft status.",
      "web_url": "http://gitlab.example.com/flightjs/flight-management",
      "avatar_url": null,
      "git_ssh_url": "ssh://git@gitlab.example.com:flightjs/flight-management.git",
      "git_http_url": "http://gitlab.example.com/flightjs/flight-management.git",
      "namespace": "Flightjs",
      "visibility_level": 0,
      "path_with_namespace": "flightjs/flight-management",
      "default_branch": "main",
      "ci_config_path": null
    },
    "state": "opened",
    "system": false,
    "target": {
      "id": 2,
      "name": "Flight Management",
      "description": "Flight management application for tracking aircraft status.",
      "web_url": "http://gitlab.example.com/flightjs/flight-management",
      "avatar_url": null,
      "git_ssh_url": "ssh://git@gitlab.example.com:flightjs/flight-management.git",
      "git_http_url": "http://gitlab.example.com/flightjs/flight-management.git",
      "namespace": "Flightjs",
      "visibility_level": 0,
      "path_with_namespace": "flightjs/flight-management",
      "default_branch": "main",
      "ci_config_path": null
    },
    "time_change": 0,
    "total_time_spent": 0,
    "url": "http://gitlab.example.com/flightjs/flight-management/-/merge_requests/16",
    "approval_rules": [
      {
        "id": 4,
        "approvals_required": 0,
        "name": "All Members",
        "rule_type": "any_approver",
        "report_type": null,
        "merge_request_id": 93,
        "section": null,
        "modified_from_project_rule": false,
        "orchestration_policy_idx": null,
        "vulnerabilities_allowed": 0,
        "scanners": [],
        "severity_levels": [],
        "vulnerability_states": [
          "new_needs_triage",
          "new_dismissed"
        ],
        "security_orchestration_policy_configuration_id": null,
        "scan_result_policy_id": null,
        "applicable_post_merge": null,
        "project_id": 2,
        "approval_policy_rule_id": null,
        "updated_at": "2026-01-16T05:56:22.000Z",
        "created_at": "2026-01-16T05:56:22.000Z"
      }
    ],
    "action": "open",
    "actioned_at": "2026-01-16T05:56:26.000Z"
  },
  "labels": [
    {
      "id": 19,
      "title": "enhancement",
      "color": "#adb21a",
      "project_id": null,
      "created_at": "2026-01-07T00:03:52.000Z",
      "updated_at": "2026-01-07T00:03:52.000Z",
      "template": false,
      "description": null,
      "type": "GroupLabel",
      "group_id": 24
    }
  ],
  "changes": {
    "merge_status": {
      "previous": "preparing",
      "current": "checking"
    },
    "updated_at": {
      "previous": "2026-01-16T05:56:22.000Z",
      "current": "2026-01-16T05:56:25.000Z"
    },
    "prepared_at": {
      "previous": null,
      "current": "2026-01-16T05:56:25.000Z"
    }
  },
  "assignees": [
    {
      "id": 1,
      "name": "Alex Garcia",
      "username": "agarcia",
      "avatar_url": "https://www.gravatar.com/avatar/1a29da0ccd099482194440fac762f5ccb4ec53227761d1859979367644a889a5?s=80&d=identicon",
      "email": "[REDACTED]"
    }
  ],
  "reviewers": [
    {
      "id": 25,
      "name": "Sidney Jones",
      "username": "sjones",
      "avatar_url": "https://www.gravatar.com/avatar/1be419860e7f852e20ca2691e6b55949f7809177e7765181da42e4448491e367?s=80&d=identicon",
      "email": "[REDACTED]",
      "state": "unreviewed",
      "re_requested": false
    }
  ]
}
```

> [!note]
> `assignee_id` 및 `merge_status` 필드는 [더 이상 사용되지 않습니다](../../../api/merge_requests.md).

## 위키 페이지 이벤트 {#wiki-page-events}

위키 페이지 이벤트는 위키 페이지가 생성되고, 업데이트되거나 삭제될 때 트리거됩니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Wiki Page Hook
```

페이로드 예제:

```json
{
  "object_kind": "wiki_page",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80\u0026d=identicon",
    "email": "admin@example.com"
  },
  "project": {
    "id": 1,
    "name": "awesome-project",
    "description": "This is awesome",
    "web_url": "http://example.com/root/awesome-project",
    "avatar_url": null,
    "git_ssh_url": "git@example.com:root/awesome-project.git",
    "git_http_url": "http://example.com/root/awesome-project.git",
    "namespace": "root",
    "visibility_level": 0,
    "path_with_namespace": "root/awesome-project",
    "default_branch": "master",
    "homepage": "http://example.com/root/awesome-project",
    "url": "git@example.com:root/awesome-project.git",
    "ssh_url": "git@example.com:root/awesome-project.git",
    "http_url": "http://example.com/root/awesome-project.git"
  },
  "wiki": {
    "web_url": "http://example.com/root/awesome-project/-/wikis/home",
    "git_ssh_url": "git@example.com:root/awesome-project.wiki.git",
    "git_http_url": "http://example.com/root/awesome-project.wiki.git",
    "path_with_namespace": "root/awesome-project.wiki",
    "default_branch": "master"
  },
  "object_attributes": {
    "title": "Awesome",
    "content": "awesome content goes here",
    "format": "markdown",
    "message": "adding an awesome page to the wiki",
    "slug": "awesome",
    "url": "http://example.com/root/awesome-project/-/wikis/awesome",
    "action": "create",
    "diff_url": "http://example.com/root/awesome-project/-/wikis/home/diff?version_id=78ee4a6705abfbff4f4132c6646dbaae9c8fb6ec",
    "version_id": "3ad67c972065298d226dd80b2b03e0fc2421e731"
  }
}
```

## 파이프라인 이벤트 {#pipeline-events}

{{< history >}}

- `object_attributes.default_branch` [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/606357)되었습니다(GitLab 19.3).

{{< /history >}}

파이프라인 이벤트는 파이프라인의 상태가 변경될 때 트리거됩니다.

차단된 사용자에 의해 트리거된 파이프라인 웹후크는 처리되지 않습니다.

파이프라인 웹후크는 `object_attributes.name`을(를) 노출합니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Pipeline Hook
```

페이로드 예제:

```json
{
  "object_kind": "pipeline",
  "object_attributes": {
    "id": 31,
    "iid": 3,
    "name": "Pipeline for branch: master",
    "ref": "master",
    "tag": false,
    "sha": "bcbb5ec396a2c0f828686f14fac9b80b780504f2",
    "before_sha": "bcbb5ec396a2c0f828686f14fac9b80b780504f2",
    "source": "merge_request_event",
    "status": "success",
    "detailed_status": "passed",
    "stages": [
      "build",
      "test",
      "deploy"
    ],
    "created_at": "2016-08-12T15:23:28.000Z",
    "finished_at": "2016-08-12T15:26:29.000Z",
    "duration": 63,
    "queued_duration": 10,
    "protected_ref": false,
    "default_branch": true,
    "variables": [
      {
        "key": "NESTOR_PROD_ENVIRONMENT",
        "value": "us-west-1"
      }
    ],
    "url": "http://example.com/gitlab-org/gitlab-test/-/pipelines/31"
  },
  "merge_request": {
    "id": 1,
    "iid": 1,
    "title": "Test",
    "source_branch": "test",
    "source_project_id": 1,
    "target_branch": "master",
    "target_project_id": 1,
    "state": "opened",
    "merge_status": "can_be_merged",
    "detailed_merge_status": "mergeable",
    "url": "http://192.168.64.1:3005/gitlab-org/gitlab-test/merge_requests/1"
  },
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
    "email": "user_email@gitlab.com"
  },
  "project": {
    "id": 1,
    "name": "Gitlab Test",
    "description": "Atque in sunt eos similique dolores voluptatem.",
    "web_url": "http://192.168.64.1:3005/gitlab-org/gitlab-test",
    "avatar_url": null,
    "git_ssh_url": "git@192.168.64.1:gitlab-org/gitlab-test.git",
    "git_http_url": "http://192.168.64.1:3005/gitlab-org/gitlab-test.git",
    "namespace": "Gitlab Org",
    "visibility_level": 20,
    "path_with_namespace": "gitlab-org/gitlab-test",
    "default_branch": "master",
    "ci_config_path": null
  },
  "commit": {
    "id": "bcbb5ec396a2c0f828686f14fac9b80b780504f2",
    "message": "test\n",
    "title": "test",
    "timestamp": "2016-08-12T17:23:21+02:00",
    "url": "http://example.com/gitlab-org/gitlab-test/commit/bcbb5ec396a2c0f828686f14fac9b80b780504f2",
    "author": {
      "name": "User",
      "email": "user@gitlab.com"
    }
  },
  "builds": [
    {
      "id": 380,
      "stage": "deploy",
      "name": "production",
      "status": "skipped",
      "created_at": "2016-08-12 15:23:28 UTC",
      "started_at": null,
      "finished_at": null,
      "duration": null,
      "queued_duration": null,
      "failure_reason": null,
      "when": "manual",
      "manual": true,
      "allow_failure": false,
      "user": {
        "id": 1,
        "name": "Administrator",
        "username": "root",
        "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
        "email": "admin@example.com"
      },
      "runner": null,
      "artifacts_file": {
        "filename": null,
        "size": null
      },
      "environment": {
        "name": "production",
        "action": "start",
        "deployment_tier": "production"
      }
    },
    {
      "id": 377,
      "stage": "test",
      "name": "test-image",
      "status": "success",
      "created_at": "2016-08-12 15:23:28 UTC",
      "started_at": "2016-08-12 15:26:12 UTC",
      "finished_at": "2016-08-12 15:26:29 UTC",
      "duration": 17.0,
      "queued_duration": 196.0,
      "failure_reason": null,
      "when": "on_success",
      "manual": false,
      "allow_failure": false,
      "user": {
        "id": 1,
        "name": "Administrator",
        "username": "root",
        "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
        "email": "admin@example.com"
      },
      "runner": {
        "id": 380987,
        "description": "shared-runners-manager-6.gitlab.com",
        "runner_type": "instance_type",
        "active": true,
        "is_shared": true,
        "tags": [
          "linux",
          "docker",
          "shared-runner"
        ]
      },
      "artifacts_file": {
        "filename": null,
        "size": null
      },
      "environment": null
    },
    {
      "id": 378,
      "stage": "test",
      "name": "test-build",
      "status": "failed",
      "created_at": "2016-08-12 15:23:28 UTC",
      "started_at": "2016-08-12 15:26:12 UTC",
      "finished_at": "2016-08-12 15:26:29 UTC",
      "duration": 17.0,
      "queued_duration": 196.0,
      "failure_reason": "script_failure",
      "when": "on_success",
      "manual": false,
      "allow_failure": false,
      "user": {
        "id": 1,
        "name": "Administrator",
        "username": "root",
        "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
        "email": "admin@example.com"
      },
      "runner": {
        "id": 380987,
        "description": "shared-runners-manager-6.gitlab.com",
        "runner_type": "instance_type",
        "active": true,
        "is_shared": true,
        "tags": [
          "linux",
          "docker"
        ]
      },
      "artifacts_file": {
        "filename": null,
        "size": null
      },
      "environment": null
    },
    {
      "id": 376,
      "stage": "build",
      "name": "build-image",
      "status": "success",
      "created_at": "2016-08-12 15:23:28 UTC",
      "started_at": "2016-08-12 15:24:56 UTC",
      "finished_at": "2016-08-12 15:25:26 UTC",
      "duration": 17.0,
      "queued_duration": 196.0,
      "failure_reason": null,
      "when": "on_success",
      "manual": false,
      "allow_failure": false,
      "user": {
        "id": 1,
        "name": "Administrator",
        "username": "root",
        "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
        "email": "admin@example.com"
      },
      "runner": {
        "id": 380987,
        "description": "shared-runners-manager-6.gitlab.com",
        "runner_type": "instance_type",
        "active": true,
        "is_shared": true,
        "tags": [
          "linux",
          "docker"
        ]
      },
      "artifacts_file": {
        "filename": null,
        "size": null
      },
      "environment": null
    },
    {
      "id": 379,
      "stage": "deploy",
      "name": "staging",
      "status": "created",
      "created_at": "2016-08-12 15:23:28 UTC",
      "started_at": null,
      "finished_at": null,
      "duration": null,
      "queued_duration": null,
      "failure_reason": null,
      "when": "on_success",
      "manual": false,
      "allow_failure": false,
      "user": {
        "id": 1,
        "name": "Administrator",
        "username": "root",
        "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
        "email": "admin@example.com"
      },
      "runner": null,
      "artifacts_file": {
        "filename": null,
        "size": null
      },
      "environment": {
        "name": "staging",
        "action": "start",
        "deployment_tier": "staging"
      }
    }
  ],
  "source_pipeline": {
    "project": {
      "id": 41,
      "web_url": "https://gitlab.example.com/gitlab-org/upstream-project",
      "path_with_namespace": "gitlab-org/upstream-project"
    },
    "pipeline_id": 30,
    "job_id": 3401
  }
}
```

## 작업 이벤트 {#job-events}

작업 이벤트는 작업 상태가 변경될 때 트리거됩니다. 트리거 작업은 제외됩니다.

페이로드의 `commit.id`은(는) 커밋의 ID가 아니라 파이프라인의 ID입니다.

차단된 사용자에 의해 트리거된 작업 이벤트는 처리되지 않습니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Job Hook
```

페이로드 예제:

```json
{
  "object_kind": "build",
  "ref": "gitlab-script-trigger",
  "tag": false,
  "before_sha": "2293ada6b400935a1378653304eaf6221e0fdb8f",
  "sha": "2293ada6b400935a1378653304eaf6221e0fdb8f",
  "retries_count": 2,
  "build_id": 1977,
  "build_name": "test",
  "build_stage": "test",
  "build_status": "created",
  "build_created_at": "2021-02-23T02:41:37.886Z",
  "build_started_at": null,
  "build_finished_at": null,
  "build_created_at_iso": "2021-02-23T02:41:37Z",
  "build_started_at_iso": null,
  "build_finished_at_iso": null,
  "build_duration": null,
  "build_queued_duration": 1095.588715,
  "build_allow_failure": false,
  "build_failure_reason": "unknown_failure",
  "pipeline_id": 2366,
  "runner": {
    "id": 380987,
    "description": "shared-runners-manager-6.gitlab.com",
    "runner_type": "project_type",
    "active": true,
    "is_shared": false,
    "tags": [
      "linux",
      "docker"
    ]
  },
  "project_id": 380,
  "project_name": "gitlab-org/gitlab-test",
  "user": {
    "id": 3,
    "name": "User",
    "username": "user",
    "avatar_url": "http://www.gravatar.com/avatar/e32bd13e2add097461cb96824b7a829c?s=80\u0026d=identicon",
    "email": "user@gitlab.com"
  },
  "commit": {
    "id": 2366,
    "name": "Build pipeline",
    "sha": "2293ada6b400935a1378653304eaf6221e0fdb8f",
    "message": "test\n",
    "author_name": "User",
    "author_email": "user@gitlab.com",
    "author_url": "http://192.168.64.1:3005/user",
    "status": "created",
    "duration": null,
    "started_at": null,
    "finished_at": null,
    "started_at_iso": null,
    "finished_at_iso": null
  },
  "repository": {
    "name": "gitlab_test",
    "url": "http://192.168.64.1:3005/gitlab-org/gitlab-test",
    "description": "Atque in sunt eos similique dolores voluptatem.",
    "homepage": "http://192.168.64.1:3005/gitlab-org/gitlab-test",
    "git_ssh_url": "git@192.168.64.1:gitlab-org/gitlab-test.git",
    "git_http_url": "http://192.168.64.1:3005/gitlab-org/gitlab-test.git",
    "visibility_level": 20
  },
  "project": {
    "id": 380,
    "name": "Gitlab Test",
    "description": "Atque in sunt eos similique dolores voluptatem.",
    "web_url": "http://192.168.64.1:3005/gitlab-org/gitlab-test",
    "avatar_url": null,
    "git_ssh_url": "git@192.168.64.1:gitlab-org/gitlab-test.git",
    "git_http_url": "http://192.168.64.1:3005/gitlab-org/gitlab-test.git",
    "namespace": "Gitlab Org",
    "visibility_level": 20,
    "path_with_namespace": "gitlab-org/gitlab-test",
    "default_branch": "master",
    "ci_config_path": null
  },
  "environment": null,
  "source_pipeline": {
    "project": {
      "id": 41,
      "web_url": "https://gitlab.example.com/gitlab-org/upstream-project",
      "path_with_namespace": "gitlab-org/upstream-project"
    },
    "pipeline_id": 30,
    "job_id": 3401
  }
}
```

### 재시도 횟수 {#number-of-retries}

`retries_count`은(는) 작업이 재시도인지 여부를 나타내는 정수입니다. `0`은(는) 작업이 재시도되지 않았음을 의미합니다. `1`은(는) 첫 번째 재시도임을 의미합니다.

### 파이프라인 이름 {#pipeline-name}

[`workflow:name`](../../../ci/yaml/_index.md#workflowname)를 사용하여 파이프라인에 대한 사용자 지정 이름을 설정할 수 있습니다. 파이프라인에 이름이 있으면 해당 이름이 `commit.name`의 값입니다.

### 실패 이유 {#failure-reason}

`build_failure_reason`은(는) [`retry:when`](../../../ci/yaml/_index.md#retrywhen)와 동일한 실패 이유 값을 사용하며 `always`을(를) 제외합니다.

작업이 실패하지 않으면 GitLab은 이 필드에서 `unknown_failure`을(를) 반환합니다. 실패 이유가 적용되지 않기 때문입니다. 작업의 성공 여부를 확인하려면 `build_status` 대신 `build_failure_reason`을(를) 사용하세요.

## 배포 이벤트 {#deployment-events}

배포 이벤트는 배포가 다음 경우에 트리거됩니다:

- 시작
- 성공
- 실패
- 취소됨
- 차단됨, 승인 대기 중 또는 수동 작업 대기 중
- 승인됨(Premium 및 Ultimate만 해당)
- 거부됨(Premium 및 Ultimate만 해당)

`status` 필드는 이벤트를 유발한 엔티티의 새 상태를 반영합니다:

- 배포 수명 주기 변경(`running`, `success`, `failed`, `canceled`, `blocked`)의 경우 필드는 배포의 현재 상태와 일치합니다.
- 승인 작업의 경우 필드는 승인 기록의 최종 상태(`approved` 또는 `rejected`)와 일치합니다.

페이로드의 `deployable_id` 및 `deployable_url`는 배포를 실행한 CI/CD 작업을 나타냅니다. 배포 이벤트가 [API](../../../ci/environments/external_deployment_tools.md) 또는 [`trigger` 작업](../../../ci/pipelines/downstream_pipelines.md)에 의해 발생할 때 `deployable_url`는 `null`입니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Deployment Hook
```

페이로드 예제:

```json
{
  "object_kind": "deployment",
  "status": "success",
  "status_changed_at":"2021-04-28T21:50:00.000+02:00",
  "deployment_id": 15,
  "deployable_id": 796,
  "deployable_url": "http://10.126.0.2:3000/root/test-deployment-webhooks/-/jobs/796",
  "environment": "staging",
  "environment_tier": "staging",
  "environment_slug": "staging",
  "environment_external_url": "https://staging.example.com",
  "project": {
    "id": 30,
    "name": "test-deployment-webhooks",
    "description": "",
    "web_url": "http://10.126.0.2:3000/root/test-deployment-webhooks",
    "avatar_url": null,
    "git_ssh_url": "ssh://vlad@10.126.0.2:2222/root/test-deployment-webhooks.git",
    "git_http_url": "http://10.126.0.2:3000/root/test-deployment-webhooks.git",
    "namespace": "Administrator",
    "visibility_level": 0,
    "path_with_namespace": "root/test-deployment-webhooks",
    "default_branch": "master",
    "ci_config_path": "",
    "homepage": "http://10.126.0.2:3000/root/test-deployment-webhooks",
    "url": "ssh://vlad@10.126.0.2:2222/root/test-deployment-webhooks.git",
    "ssh_url": "ssh://vlad@10.126.0.2:2222/root/test-deployment-webhooks.git",
    "http_url": "http://10.126.0.2:3000/root/test-deployment-webhooks.git"
  },
  "short_sha": "279484c0",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "https://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
    "email": "admin@example.com"
  },
  "user_url": "http://10.126.0.2:3000/root",
  "commit_url": "http://10.126.0.2:3000/root/test-deployment-webhooks/-/commit/279484c09fbe69ededfced8c1bb6e6d24616b468",
  "commit_title": "Add new file"
}
```

### 배포 승인 및 거부 이벤트 {#deployment-approval-and-rejection-events}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/441402)되었습니다.

{{< /history >}}

[보호 환경](../../../ci/environments/deployment_approvals.md)으로의 배포가 승인이 필요하면 승인자가 배포를 승인하거나 거부할 때마다 배포 웹후크를 발생시킵니다. 페이로드는 다른 배포 이벤트와 동일한 `object_kind`를 유지하고 승인 관련 필드를 추가합니다:

- `status`는 `approved` 또는 `rejected`이며 승인 작업을 반영합니다.
- `status_changed_at`은(는) 승인이 기록된 시간이며 ISO 8601 형식입니다.
- `approver`은(는) 승인 또는 거부를 기록한 사용자입니다. `approver.email` 필드는 승인자가 이메일을 공개하지 않은 경우 `[REDACTED]`입니다.
- `approval`은(는) 승인을 설명하며 승인을 허가한 보호 환경 규칙을 포함합니다. `approval.approval_rule.access_level_description` 필드는 규칙에 대한 사람이 읽을 수 있는 레이블입니다.
  - 역할 기반 규칙의 경우 필드는 `"Maintainers"`과 같은 로캘 독립 레이블입니다.
  - 사용자 범위 또는 그룹 범위 규칙의 경우 사용자 또는 그룹의 표시 이름(사용자 제어 문자열)입니다. 수신자는 이 필드를 신뢰할 수 없는 표시 텍스트로 처리하고 기계 읽을 수 있는 라우팅에 `user_id`, `group_id` 및 `access_level`을(를) 사용해야 합니다.

`approver` 및 `approval` 필드는 승인 및 거부 이벤트에만 특정되며 다른 배포 수명 주기 이벤트에는 표시되지 않습니다. 수신자는 `status`의 값으로 또는 이러한 필드의 존재로 승인 이벤트를 식별할 수 있습니다.

페이로드 예제:

```json
{
  "object_kind": "deployment",
  "status": "approved",
  "status_changed_at": "2026-05-08T10:30:00.000Z",
  "deployment_id": 15,
  "deployable_id": 796,
  "deployable_url": "http://10.126.0.2:3000/root/test-deployment-webhooks/-/jobs/796",
  "environment": "production",
  "environment_tier": "production",
  "environment_slug": "production",
  "environment_external_url": "https://production.example.com",
  "project": {
    "id": 30,
    "name": "test-deployment-webhooks",
    "web_url": "http://10.126.0.2:3000/root/test-deployment-webhooks",
    "path_with_namespace": "root/test-deployment-webhooks"
  },
  "short_sha": "279484c0",
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "https://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
    "email": "admin@example.com"
  },
  "user_url": "http://10.126.0.2:3000/root",
  "commit_url": "http://10.126.0.2:3000/root/test-deployment-webhooks/-/commit/279484c09fbe69ededfced8c1bb6e6d24616b468",
  "commit_title": "Add new file",
  "approver": {
    "id": 5,
    "name": "Ops Lead",
    "username": "ops_lead",
    "avatar_url": "https://www.gravatar.com/avatar/abcdef1234567890?s=80&d=identicon",
    "email": "ops@example.com"
  },
  "approval": {
    "id": 42,
    "status": "approved",
    "comment": "LGTM",
    "created_at": "2026-05-08T10:30:00.000Z",
    "approval_rule": {
      "id": 7,
      "user_id": null,
      "group_id": null,
      "access_level": 40,
      "access_level_description": "Maintainers",
      "required_approvals": 2,
      "group_inheritance_type": 0
    }
  }
}
```

거부의 경우 `status` 및 `approval.status` 모두 `rejected`입니다. `approval.approval_rule` 값은 보호 환경이 승인 규칙을 사용하지 않을 때 `null`입니다.

#### 거부 및 완전한 승인 주변 이벤트 시퀀스 {#event-sequence-around-rejection-and-full-approval}

승인 및 수명 주기 웹후크는 독립적입니다. 승인 워크플로우를 거치는 배포는 동일한 `deployment_id`을(를) 사용하여 여러 웹후크를 생성합니다. 배포가 승인 대기 상태에 들어가면 `status: "blocked"` 이벤트가 먼저 발생합니다. 그 후 승인 또는 거부 작업이 자체 이벤트를 생성합니다.

이벤트는 다음 순서로 발생합니다:

1. 배포가 처음 승인 대기 상태에 들어가면 `status: "blocked"` 이벤트가 발생합니다. 이것은 배포 수명 주기 이벤트이며 승인 필드를 포함하지 않습니다.
1. 그 다음 거부는 `status: "rejected"`을(를) 생성합니다(`approver` 및 `approval` 포함). 그 다음 배포 작업이 삭제될 때 동일한 배포에 대해 `status: "failed"`입니다. `failed` 이벤트는 기존 레거시 수명 주기 이벤트이며 승인 필드를 포함하지 않습니다.
1. 최종 승인은 `status: "approved"`을(를) 생성한 후 배포 작업이 시작될 때 `status: "running"`를 생성하고 `status: "success"` 또는 `status: "failed"`와 같은 최종 이벤트를 생성합니다.

거부로 인한 중복 실패 경고 처리에 대한 지침은 [웹후크 문제 해결](webhooks_troubleshooting.md#duplicate-deployment-failure-alerts-after-a-rejection)을 참조하세요.

## 그룹 구성원 이벤트 {#group-member-events}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

{{< history >}}

- 액세스 요청 이벤트가 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163094)되었습니다(GitLab 17.4).

{{< /history >}}

이러한 이벤트는 [그룹 웹후크](webhooks.md#group-webhooks)에만 대해 트리거됩니다.

구성원 이벤트는 다음 경우에 트리거됩니다:

- 사용자가 그룹 구성원으로 추가됩니다.
- 사용자의 액세스 수준이 변경됩니다.
- 사용자 액세스의 만료 날짜가 업데이트됩니다.
- 사용자가 그룹에서 제거됩니다.
- 사용자가 그룹에 대한 액세스를 요청합니다.
- 액세스 요청이 거부됩니다.

### 그룹에 구성원 추가 {#add-member-to-group}

요청 헤더:

```plaintext
X-Gitlab-Event: Member Hook
```

페이로드 예제:

```json
{
  "created_at": "2020-12-11T04:57:22Z",
  "updated_at": "2020-12-11T04:57:22Z",
  "group_name": "webhook-test",
  "group_path": "webhook-test",
  "group_id": 100,
  "user_username": "test_user",
  "user_name": "Test User",
  "user_email": "testuser@webhooktest.com",
  "user_id": 64,
  "group_access": "Guest",
  "group_plan": null,
  "expires_at": "2020-12-14T00:00:00Z",
  "event_name": "user_add_to_group"
}
```

### 구성원 액세스 수준 또는 만료 날짜 업데이트 {#update-member-access-level-or-expiration-date}

요청 헤더:

```plaintext
X-Gitlab-Event: Member Hook
```

페이로드 예제:

```json
{
  "created_at": "2020-12-11T04:57:22Z",
  "updated_at": "2020-12-12T08:48:19Z",
  "group_name": "webhook-test",
  "group_path": "webhook-test",
  "group_id": 100,
  "user_username": "test_user",
  "user_name": "Test User",
  "user_email": "testuser@webhooktest.com",
  "user_id": 64,
  "group_access": "Developer",
  "group_plan": null,
  "expires_at": "2020-12-20T00:00:00Z",
  "event_name": "user_update_for_group"
}
```

### 그룹에서 구성원 제거 {#remove-member-from-group}

요청 헤더:

```plaintext
X-Gitlab-Event: Member Hook
```

페이로드 예제:

```json
{
  "created_at": "2020-12-11T04:57:22Z",
  "updated_at": "2020-12-12T08:52:34Z",
  "group_name": "webhook-test",
  "group_path": "webhook-test",
  "group_id": 100,
  "user_username": "test_user",
  "user_name": "Test User",
  "user_email": "testuser@webhooktest.com",
  "user_id": 64,
  "group_access": "Guest",
  "group_plan": null,
  "expires_at": "2020-12-14T00:00:00Z",
  "event_name": "user_remove_from_group"
}
```

### 사용자가 액세스를 요청합니다 {#a-user-requests-access}

{{< history >}}

- `group_access_request_webhooks`라는 이름의 [기능 플래그](../../../administration/feature_flags/_index.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163094)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.5에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/479877)입니다. 기능 플래그 `group_access_request_webhooks`이 제거되었습니다.

{{< /history >}}

요청 헤더:

```plaintext
X-Gitlab-Event: Member Hook
```

페이로드 예제:

```json
{
  "created_at": "2020-12-11T04:57:22Z",
  "updated_at": "2020-12-12T08:52:34Z",
  "group_name": "webhook-test",
  "group_path": "webhook-test",
  "group_id": 100,
  "user_username": "test_user",
  "user_name": "Test User",
  "user_email": "testuser@webhooktest.com",
  "user_id": 64,
  "group_access": "Guest",
  "group_plan": null,
  "expires_at": "2020-12-14T00:00:00Z",
  "event_name": "user_access_request_to_group"
}
```

### 액세스 요청이 거부됨 {#an-access-request-is-denied}

{{< history >}}

- `group_access_request_webhooks`라는 이름의 [기능 플래그](../../../administration/feature_flags/_index.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163094)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.5에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/479877)입니다. 기능 플래그 `group_access_request_webhooks`이 제거되었습니다.

{{< /history >}}

요청 헤더:

```plaintext
X-Gitlab-Event: Member Hook
```

페이로드 예제:

```json
{
  "created_at": "2020-12-11T04:57:22Z",
  "updated_at": "2020-12-12T08:52:34Z",
  "group_name": "webhook-test",
  "group_path": "webhook-test",
  "group_id": 100,
  "user_username": "test_user",
  "user_name": "Test User",
  "user_email": "testuser@webhooktest.com",
  "user_id": 64,
  "group_access": "Guest",
  "group_plan": null,
  "expires_at": "2020-12-14T00:00:00Z",
  "event_name": "user_access_request_denied_for_group"
}
```

## 프로젝트 이벤트 {#project-events}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

{{< history >}}

- GitLab 17.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/359044)되었습니다.

{{< /history >}}

이러한 이벤트는 [그룹 웹후크](webhooks.md#group-webhooks)에만 대해 트리거됩니다.

프로젝트 이벤트는 다음 경우에 트리거됩니다:

- [그룹에서 프로젝트가 생성](#create-a-project-in-a-group)됩니다.
- [그룹에서 프로젝트가 삭제](#delete-a-project-in-a-group)됩니다.

### 그룹에서 프로젝트 생성 {#create-a-project-in-a-group}

요청 헤더:

```plaintext
X-Gitlab-Event: Project Hook
```

페이로드 예제:

```json
{
  "event_name": "project_create",
  "created_at": "2024-10-07T10:43:48Z",
  "updated_at": "2024-10-07T10:43:48Z",
  "name": "project1",
  "path": "project1",
  "path_with_namespace": "group1/project1",
  "project_id": 22,
  "project_namespace_id": 32,
  "owners": [{
    "name": "John",
    "email": "user1@example.com"
  }],
  "project_visibility": "private"
}
```

### 그룹에서 프로젝트 삭제 {#delete-a-project-in-a-group}

요청 헤더:

```plaintext
X-Gitlab-Event: Project Hook
```

페이로드 예제:

```json
{
  "event_name": "project_destroy",
  "created_at": "2024-10-07T10:43:48Z",
  "updated_at": "2024-10-07T10:43:48Z",
  "name": "project1",
  "path": "project1",
  "path_with_namespace": "group1/project1",
  "project_id": 22,
  "project_namespace_id": 32,
  "owners": [{
    "name": "John",
    "email": "user1@example.com"
  }],
  "project_visibility": "private"
}
```

## 서브그룹 이벤트 {#subgroup-events}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

이러한 이벤트는 [그룹 웹후크](webhooks.md#group-webhooks)에만 대해 트리거됩니다.

서브그룹 이벤트는 다음 경우에 트리거됩니다:

- [그룹에서 서브그룹이 생성](#create-a-subgroup-in-a-group)됩니다.
- [그룹에서 서브그룹이 제거](#remove-a-subgroup-from-a-group)됩니다.

### 그룹에서 서브그룹 생성 {#create-a-subgroup-in-a-group}

요청 헤더:

```plaintext
X-Gitlab-Event: Subgroup Hook
```

페이로드 예제:

```json
{

  "created_at": "2021-01-20T09:40:12Z",
  "updated_at": "2021-01-20T09:40:12Z",
  "event_name": "subgroup_create",
  "name": "subgroup1",
  "path": "subgroup1",
  "full_path": "group1/subgroup1",
  "group_id": 10,
  "parent_group_id": 7,
  "parent_name": "group1",
  "parent_path": "group1",
  "parent_full_path": "group1"

}
```

### 그룹에서 서브그룹 제거 {#remove-a-subgroup-from-a-group}

이 웹후크는 [서브그룹이 새 부모 그룹으로 전송](../../group/manage.md#transfer-a-group)될 때 트리거되지 않습니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Subgroup Hook
```

페이로드 예제:

```json
{

  "created_at": "2021-01-20T09:40:12Z",
  "updated_at": "2021-01-20T09:40:12Z",
  "event_name": "subgroup_destroy",
  "name": "subgroup1",
  "path": "subgroup1",
  "full_path": "group1/subgroup1",
  "group_id": 10,
  "parent_group_id": 7,
  "parent_name": "group1",
  "parent_path": "group1",
  "parent_full_path": "group1"

}
```

## 기능 플래그 이벤트 {#feature-flag-events}

기능 플래그 이벤트는 기능 플래그이 켜지거나 꺼질 때 트리거됩니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Feature Flag Hook
```

페이로드 예제:

```json
{
  "object_kind": "feature_flag",
  "project": {
    "id": 1,
    "name":"Gitlab Test",
    "description":"Aut reprehenderit ut est.",
    "web_url":"http://example.com/gitlabhq/gitlab-test",
    "avatar_url":null,
    "git_ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "git_http_url":"http://example.com/gitlabhq/gitlab-test.git",
    "namespace":"GitlabHQ",
    "visibility_level":20,
    "path_with_namespace":"gitlabhq/gitlab-test",
    "default_branch":"master",
    "ci_config_path": null,
    "homepage":"http://example.com/gitlabhq/gitlab-test",
    "url":"http://example.com/gitlabhq/gitlab-test.git",
    "ssh_url":"git@example.com:gitlabhq/gitlab-test.git",
    "http_url":"http://example.com/gitlabhq/gitlab-test.git"
  },
  "user": {
    "id": 1,
    "name": "Administrator",
    "username": "root",
    "avatar_url": "https://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
    "email": "admin@example.com"
  },
  "user_url": "http://example.com/root",
  "object_attributes": {
    "id": 6,
    "name": "test-feature-flag",
    "description": "test-feature-flag-description",
    "active": true
  }
}
```

## 릴리스 이벤트 {#release-events}

릴리스 이벤트는 릴리스가 생성되거나, 업데이트되거나, 삭제될 때 트리거됩니다.

페이로드의 `object_attributes.action` 사용 가능한 값은 다음과 같습니다:

- `create`
- `update`
- `delete`

요청 헤더:

```plaintext
X-Gitlab-Event: Release Hook
```

페이로드 예제:

```json
{
  "id": 1,
  "created_at": "2020-11-02T12:55:12.000Z",
  "description": "v1.1 has been released",
  "name": "v1.1",
  "released_at": "2020-11-02T12:55:12.000Z",
  "tag": "v1.1",
  "object_kind": "release",
  "project": {
    "id": 2,
    "name": "release-webhook-example",
    "description": "",
    "web_url": "https://example.com/gitlab-org/release-webhook-example",
    "avatar_url": null,
    "git_ssh_url": "ssh://git@example.com/gitlab-org/release-webhook-example.git",
    "git_http_url": "https://example.com/gitlab-org/release-webhook-example.git",
    "namespace": "Gitlab",
    "visibility_level": 0,
    "path_with_namespace": "gitlab-org/release-webhook-example",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "https://example.com/gitlab-org/release-webhook-example",
    "url": "ssh://git@example.com/gitlab-org/release-webhook-example.git",
    "ssh_url": "ssh://git@example.com/gitlab-org/release-webhook-example.git",
    "http_url": "https://example.com/gitlab-org/release-webhook-example.git"
  },
  "url": "https://example.com/gitlab-org/release-webhook-example/-/releases/v1.1",
  "action": "create",
  "assets": {
    "count": 5,
    "links": [
      {
        "id": 1,
        "link_type": "other",
        "name": "Changelog",
        "url": "https://example.net/changelog"
      }
    ],
    "sources": [
      {
        "format": "zip",
        "url": "https://example.com/gitlab-org/release-webhook-example/-/archive/v1.1/release-webhook-example-v1.1.zip"
      },
      {
        "format": "tar.gz",
        "url": "https://example.com/gitlab-org/release-webhook-example/-/archive/v1.1/release-webhook-example-v1.1.tar.gz"
      },
      {
        "format": "tar.bz2",
        "url": "https://example.com/gitlab-org/release-webhook-example/-/archive/v1.1/release-webhook-example-v1.1.tar.bz2"
      },
      {
        "format": "tar",
        "url": "https://example.com/gitlab-org/release-webhook-example/-/archive/v1.1/release-webhook-example-v1.1.tar"
      }
    ]
  },
  "commit": {
    "id": "ee0a3fb31ac16e11b9dbb596ad16d4af654d08f8",
    "message": "Release v1.1",
    "title": "Release v1.1",
    "timestamp": "2020-10-31T14:58:32+11:00",
    "url": "https://example.com/gitlab-org/release-webhook-example/-/commit/ee0a3fb31ac16e11b9dbb596ad16d4af654d08f8",
    "author": {
      "name": "Example User",
      "email": "user@example.com"
    }
  }
}
```

## 마일스톤 이벤트 {#milestone-events}

{{< history >}}

- GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/14213)되었습니다.

{{< /history >}}

마일스톤 이벤트는 마일스톤이 생성되고, 닫히고, 다시 열리거나 삭제될 때 트리거됩니다.

페이로드의 `object_attributes.action` 사용 가능한 값은 다음과 같습니다:

- `create`
- `close`
- `reopen`

요청 헤더:

```plaintext
X-Gitlab-Event: Milestone Hook
```

페이로드 예제:

```json
{
  "object_kind": "milestone",
  "event_type": "milestone",
  "project": {
    "id": 1,
    "name": "Gitlab Test",
    "description": "Aut reprehenderit ut est.",
    "web_url": "http://example.com/gitlabhq/gitlab-test",
    "avatar_url": null,
    "git_ssh_url": "git@example.com:gitlabhq/gitlab-test.git",
    "git_http_url": "http://example.com/gitlabhq/gitlab-test.git",
    "namespace": "GitlabHQ",
    "visibility_level": 20,
    "path_with_namespace": "gitlabhq/gitlab-test",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "http://example.com/gitlabhq/gitlab-test",
    "url": "http://example.com/gitlabhq/gitlab-test.git",
    "ssh_url": "git@example.com:gitlabhq/gitlab-test.git",
    "http_url": "http://example.com/gitlabhq/gitlab-test.git"
  },
  "object_attributes": {
    "id": 61,
    "iid": 10,
    "title": "v1.0",
    "description": "First stable release",
    "state": "active",
    "created_at": "2025-06-16T14:10:57.000Z",
    "updated_at": "2025-06-16T14:10:57.000Z",
    "due_date": "2025-06-30",
    "start_date": "2025-06-16",
    "group_id": null,
    "project_id": 1
  },
  "action": "create"
}
```

## 이모지 이벤트 {#emoji-events}

{{< history >}}

- [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/123952)되었습니다(GitLab 16.2) [기능 플래그](../../../administration/feature_flags/_index.md) `emoji_webhooks`로 명명되었습니다. 기본적으로 비활성화되었습니다.
- GitLab.com에서 [활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/417288)되었습니다(GitLab 16.3).
- 기본적으로 [활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/417288)되었습니다(GitLab 16.4).
- GitLab 17.5에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/417288)입니다. 기능 플래그 `emoji_webhooks`이 제거되었습니다.

{{< /history >}}

이모지 이벤트는 [이모지 반응](../../emoji_reactions.md)이 다음에 추가되거나 제거될 때 트리거됩니다:

- 이슈
- 병합 요청
- 프로젝트 스니펫
- 위키 페이지
- 댓글:
  - 이슈
  - 병합 요청
  - 프로젝트 스니펫
  - 위키 페이지
  - 커밋

페이로드의 `object_attributes.action` 사용 가능한 값은 다음과 같습니다:

- 반응을 추가하려면 `award`
- 반응을 제거하려면 `revoke`

요청 헤더:

```plaintext
X-Gitlab-Event: Emoji Hook
```

페이로드 예제:

```json
{
  "object_kind": "emoji",
  "event_type": "award",
  "user": {
    "id": 1,
    "name": "Blake Bergstrom",
    "username": "root",
    "avatar_url": "http://example.com/uploads/-/system/user/avatar/1/avatar.png",
    "email": "[REDACTED]"
  },
  "project_id": 6,
  "project": {
    "id": 6,
    "name": "Flight",
    "description": "Velit fugit aperiam illum deleniti odio sequi.",
    "web_url": "http://example.com/flightjs/Flight",
    "avatar_url": null,
    "git_ssh_url": "ssh://git@example.com/flightjs/Flight.git",
    "git_http_url": "http://example.com/flightjs/Flight.git",
    "namespace": "Flightjs",
    "visibility_level": 20,
    "path_with_namespace": "flightjs/Flight",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "http://example.com/flightjs/Flight",
    "url": "ssh://git@example.com/flightjs/Flight.git",
    "ssh_url": "ssh://git@example.com/flightjs/Flight.git",
    "http_url": "http://example.com/flightjs/Flight.git"
  },
  "object_attributes": {
    "user_id": 1,
    "created_at": "2023-07-04T20:44:11.000Z",
    "id": 1,
    "name": "thumbsup",
    "awardable_type": "Note",
    "awardable_id": 363,
    "updated_at": "2023-07-04T20:44:11.000Z",
    "action": "award",
    "awarded_on_url": "http://example.com/flightjs/Flight/-/issues/42#note_363"
  },
  "note": {
    "attachment": null,
    "author_id": 1,
    "change_position": null,
    "commit_id": null,
    "created_at": "2023-07-04T15:09:55.000Z",
    "discussion_id": "c3d97fd471f210a5dc8b97a409e3bea95ee06c14",
    "id": 363,
    "line_code": null,
    "note": "Testing 123",
    "noteable_id": 635,
    "noteable_type": "Issue",
    "original_position": null,
    "position": null,
    "project_id": 6,
    "resolved_at": null,
    "resolved_by_id": null,
    "resolved_by_push": null,
    "st_diff": null,
    "system": false,
    "type": null,
    "updated_at": "2023-07-04T19:58:46.000Z",
    "updated_by_id": null,
    "description": "Testing 123",
    "url": "http://example.com/flightjs/Flight/-/issues/42#note_363"
  },
  "issue": {
    "author_id": 1,
    "closed_at": null,
    "confidential": false,
    "created_at": "2023-07-04T14:59:43.000Z",
    "description": "Issue description!",
    "discussion_locked": null,
    "due_date": null,
    "id": 635,
    "iid": 42,
    "last_edited_at": null,
    "last_edited_by_id": null,
    "milestone_id": null,
    "moved_to_id": null,
    "duplicated_to_id": null,
    "project_id": 6,
    "relative_position": 18981,
    "state_id": 1,
    "time_estimate": 0,
    "title": "New issue!",
    "updated_at": "2023-07-04T15:09:55.000Z",
    "updated_by_id": null,
    "weight": null,
    "health_status": null,
    "url": "http://example.com/flightjs/Flight/-/issues/42",
    "total_time_spent": 0,
    "time_change": 0,
    "human_total_time_spent": null,
    "human_time_change": null,
    "human_time_estimate": null,
    "assignee_ids": [
      1
    ],
    "assignee_id": 1,
    "labels": [

    ],
    "state": "opened",
    "severity": "unknown"
  }
}
```

## 프로젝트 및 그룹 액세스 토큰 이벤트 {#project-and-group-access-token-events}

{{< history >}}

- `full_path` 특성이 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/465421)되었습니다(GitLab 17.4).
- 60일 및 30일 알림이 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/173792)되었습니다(GitLab 17.7).

{{< /history >}}

액세스 토큰 만료 이벤트는 [액세스 토큰](../../../security/tokens/_index.md)이 만료되기 전에 트리거됩니다. 이러한 이벤트는 다음을 트리거합니다:

- 토큰이 만료되기 7일 전
- 토큰이 만료되기 30일 전(구성 필요)
- 토큰이 만료되기 60일 전(구성 필요)

30일 및 60일 알림을 구성하는 방법에 대한 정보는 다음을 참조하세요:

- [프로젝트 액세스 토큰 만료에 대한 추가 웹후크 트리거 추가](../settings/_index.md#add-additional-webhook-triggers-for-project-access-token-expiration)
- [그룹 액세스 토큰 만료에 대한 추가 웹후크 트리거 추가](../../group/manage.md#add-additional-webhook-triggers-for-group-access-token-expiration)

페이로드의 `event_name` 사용 가능한 값은 다음과 같습니다:

- `expiring_access_token`

요청 헤더:

```plaintext
X-Gitlab-Event: Resource Access Token Hook
```

프로젝트의 페이로드 예제:

```json
{
  "object_kind": "access_token",
  "project": {
    "id": 7,
    "name": "Flight",
    "description": "Eum dolore maxime atque reprehenderit voluptatem.",
    "web_url": "https://example.com/flightjs/Flight",
    "avatar_url": null,
    "git_ssh_url": "ssh://git@example.com/flightjs/Flight.git",
    "git_http_url": "https://example.com/flightjs/Flight.git",
    "namespace": "Flightjs",
    "visibility_level": 0,
    "path_with_namespace": "flightjs/Flight",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "https://example.com/flightjs/Flight",
    "url": "ssh://git@example.com/flightjs/Flight.git",
    "ssh_url": "ssh://git@example.com/flightjs/Flight.git",
    "http_url": "https://example.com/flightjs/Flight.git"
  },
  "object_attributes": {
    "user_id": 90,
    "created_at": "2024-01-24T16:27:40.000Z",
    "id": 25,
    "name": "acd",
    "expires_at": "2024-01-26",
    "last_used_at": "2024-01-20T10:15:30.000Z"
  },
  "event_name": "expiring_access_token"
}
```

그룹의 페이로드 예제:

```json
{
  "object_kind": "access_token",
  "group": {
    "group_name": "Twitter",
    "group_path": "twitter",
    "group_id": 35,
    "full_path": "twitter"
  },
  "object_attributes": {
    "user_id": 90,
    "created_at": "2024-01-24T16:27:40.000Z",
    "id": 25,
    "name": "acd",
    "expires_at": "2024-01-26",
    "last_used_at": "2024-01-20T10:15:30.000Z"
  },
  "event_name": "expiring_access_token"
}
```

## 프로젝트 및 그룹 배포 토큰 이벤트 {#project-and-group-deploy-token-events}

{{< history >}}

- [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/196804)되었습니다(GitLab 18.4) [기능 플래그](../../../administration/feature_flags/_index.md) `project_deploy_token_expiring_notifications`로 명명되었습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

배포 토큰 만료 이벤트는 [배포 토큰](../../../security/tokens/_index.md)이 만료되기 전에 트리거됩니다. 이러한 이벤트는 다음을 트리거합니다:

- 토큰이 만료되기 7일 전.
- 토큰이 만료되기 30일 전.
- 토큰이 만료되기 60일 전.

페이로드의 `event_name` 사용 가능한 값은 다음과 같습니다:

- `expiring_deploy_token`

요청 헤더:

```plaintext
X-Gitlab-Event: Resource Deploy Token Hook
```

프로젝트의 페이로드 예제:

```json
{
  "object_kind": "deploy_token",
  "project": {
    "id": 2,
    "name": "Gitlab Test",
    "description": "Voluptates sit architecto quos distinctio.",
    "web_url": "https://gitlab.example.com/gitlab-org/gitlab-test",
    "avatar_url": null,
    "git_ssh_url": "ssh://git@gitlab.example.com:2222/gitlab-org/gitlab-test.git",
    "git_http_url": "https://gitlab.example.com/gitlab-org/gitlab-test.git",
    "namespace": "Gitlab Org",
    "visibility_level": 10,
    "path_with_namespace": "gitlab-org/gitlab-test",
    "default_branch": "master",
    "ci_config_path": null,
    "homepage": "https://gitlab.example.com/gitlab-org/gitlab-test",
    "url": "ssh://git@gitlab.example.com:2222/gitlab-org/gitlab-test.git",
    "ssh_url": "ssh://git@gitlab.example.com:2222/gitlab-org/gitlab-test.git",
    "http_url": "https://gitlab.example.com/gitlab-org/gitlab-test.git"
  },
  "object_attributes": {
    "id": 79,
    "name": "seven-days-6days",
    "expires_at": "2025-08-03T07:57:25.000Z",
    "created_at": "2025-07-28T07:57:25.000Z",
    "revoked": false,
    "deploy_token_type": "project_type"
  },
  "event_name": "expiring_deploy_token"
}
```

## 취약성 이벤트 {#vulnerability-events}

{{< history >}}

- [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169701)되었습니다(GitLab 17.7) [기능 플래그](../../../administration/feature_flags/_index.md) `vulnerabilities_as_webhook_events`로 명명되었습니다. 기본적으로 비활성화되었습니다.
- 취약성이 생성되거나 문제가 취약성에 연결될 때 이벤트 생성이 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/176064)되었습니다(GitLab 17.8).
- GitLab 17.11에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/528397)입니다. 기능 플래그 `vulnerabilities_as_webhook_events`이 제거되었습니다.

{{< /history >}}

취약성 이벤트는 다음 경우에 트리거됩니다:

- 취약성이 생성됩니다.
- [취약성의 상태가 변경](../../application_security/vulnerabilities/_index.md#vulnerability-status-values)됩니다.
- 이슈가 취약성에 연결됩니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Vulnerability Hook
```

페이로드 예제:

```json
{
  "object_kind": "vulnerability",
  "object_attributes": {
    "url": "https://example.com/flightjs/Flight/-/security/vulnerabilities/1",
    "title": "REXML DoS vulnerability",
    "state": "confirmed",
    "project_id": 50,
    "location": {
      "file": "Gemfile.lock",
      "dependency": {
        "package": {
          "name": "rexml"
        },
        "version": "3.3.1"
      }
    },
    "cvss": [
      {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "vendor": "NVD"
      }
    ],
    "severity": "high",
    "severity_overridden": false,
    "identifiers": [
      {
        "name": "Gemnasium-29dce398-220a-4315-8c84-16cd8b6d9b05",
        "external_id": "29dce398-220a-4315-8c84-16cd8b6d9b05",
        "external_type": "gemnasium",
        "url": "https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/blob/master/gem/rexml/CVE-2024-41123.yml"
      },
      {
        "name": "CVE-2024-41123",
        "external_id": "CVE-2024-41123",
        "external_type": "cve",
        "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41123"
      }
    ],
    "issues": [
      {
        "title": "REXML ReDoS vulnerability",
        "url": "https://example.com/flightjs/Flight/-/issues/1",
        "created_at": "2025-01-08T00:46:14.429Z",
        "updated_at": "2025-01-08T00:46:14.429Z"
      }
    ],
    "report_type": "dependency_scanning",
    "scanner_external_id": "gitlab-sbom-vulnerability-scanner",
    "confidence": "unknown",
    "confidence_overridden": false,
    "confirmed_at": "2025-01-08T00:46:14.413Z",
    "confirmed_by_id": 1,
    "dismissed_at": null,
    "dismissed_by_id": null,
    "resolved_at": null,
    "resolved_by_id": null,
    "auto_resolved": false,
    "resolved_on_default_branch": false,
    "created_at": "2025-01-08T00:46:14.413Z",
    "updated_at": "2025-01-08T00:46:14.413Z"
  }
}
```

## GitLab Duo 플로우 이벤트 {#gitlab-duo-flow-events}

{{< details >}}

- 티어: [Free](../../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed
- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- [GitLab 19.4에서 도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249145)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `duo_flow_callback_hooks`로 명명됩니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트 가능하지만 프로덕션 사용은 준비되지 않았습니다.

웹후크를 참조하는 [GitLab Duo 플로우](../../duo_agent_platform/flows/_index.md)의 상태가 변경되면 GitLab Duo 플로우 이벤트가 트리거됩니다.

GitLab Duo 플로우 이벤트를 받으려면 웹후크에 대해 [웹후크 콜백](../../duo_agent_platform/flows/webhook_callbacks.md)을 켠 후 플로우를 트리거할 때 웹후크를 참조합니다. GitLab은 웹후크를 참조하는 플로우에만 이벤트를 전송합니다.

다른 이벤트 유형과 달리 GitLab Duo 플로우 이벤트는 웹후크의 **트리거** 섹션에서 선택되지 않습니다.

요청 헤더:

```plaintext
X-Gitlab-Event: Duo Flow Callback
```

GitLab은 다음 이벤트를 전송합니다:

| 이벤트            | 트리거 |
|------------------|---------|
| `flow.started`   | 에이전트가 플로우 작업을 시작합니다. |
| `flow.completed` | 플로우가 완료되고 최종 메시지를 생성합니다. |
| `flow.failed`    | 플로우가 실패하거나 최종 메시지 없이 완료됩니다. |

`flow.completed`의 페이로드 예제:

```json
{
  "object_kind": "duo_workflow",
  "version": "1",
  "event": "flow.completed",
  "event_id": "f5e5f430-f57b-4e6e-9fac-d9128cd7232f",
  "client_reference": "run-abc123",
  "result": {
    "message": "I corrected the indentation in .gitlab-ci.yml and pushed the change."
  },
  "project": {
    "id": 5,
    "name": "Flight",
    "description": "Example project",
    "web_url": "https://gitlab.example.com/flightjs/Flight",
    "avatar_url": null,
    "git_ssh_url": "git@gitlab.example.com:flightjs/Flight.git",
    "git_http_url": "https://gitlab.example.com/flightjs/Flight.git",
    "namespace": "Flightjs",
    "visibility_level": 20,
    "path_with_namespace": "flightjs/Flight",
    "default_branch": "main",
    "ci_config_path": null,
    "homepage": "https://gitlab.example.com/flightjs/Flight",
    "url": "git@gitlab.example.com:flightjs/Flight.git",
    "ssh_url": "git@gitlab.example.com:flightjs/Flight.git",
    "http_url": "https://gitlab.example.com/flightjs/Flight.git"
  },
  "user": {
    "id": 1,
    "name": "Sidney Jones",
    "username": "sidney_jones",
    "avatar_url": "https://gitlab.example.com/uploads/-/system/user/avatar/1/avatar.png",
    "email": "[REDACTED]"
  },
  "workflow": {
    "id": 1,
    "status": "finished",
    "web_url": "https://gitlab.example.com/flightjs/Flight/-/automate/agent-sessions/1"
  }
}
```

페이로드 특성:

| 특성          | 형식    | 설명 |
|--------------------|---------|-------------|
| `client_reference` | 문자열  | 플로우를 트리거한 요청의 `client_reference` 특성 값입니다. 요청에서 설정하지 않은 경우 생략됩니다. |
| `error`            | 객체  | 플로우가 실패한 이유입니다. `flow.failed`에만 표시됩니다. `reason`만 포함됩니다. |
| `error.reason`     | 문자열  | 머신 가독형 실패 이유입니다. `flow_failed`은 플로우 자체가 실패했을 때이고, `no_response`은 플로우가 최종 메시지 없이 완료되었을 때입니다. `no_response` 이벤트의 `workflow.status`은 `finished`입니다. |
| `event`            | 문자열  | 이벤트 이름입니다. `flow.started`, `flow.completed` 또는 `flow.failed` 중 하나입니다. |
| `event_id`         | 문자열  | 이벤트의 ID입니다. GitLab이 배달을 다시 시도할 때 반복됩니다. 이미 처리한 이벤트를 무시하는 데 사용합니다. |
| `object_kind`      | 문자열  | 항상 `duo_workflow`입니다. |
| `project`          | 객체  | 플로우가 실행된 프로젝트입니다. 그룹에서 실행된 플로우의 경우 생략됩니다. |
| `result`           | 객체  | 플로우의 최종 출력입니다. `flow.completed`에만 표시됩니다. |
| `result.message`   | 문자열  | 에이전트로부터의 최종 메시지입니다. |
| `user`             | 객체  | 플로우를 트리거한 사용자입니다. |
| `version`          | 문자열  | 페이로드 구조의 버전입니다. 항상 `1`입니다. |
| `workflow`         | 객체  | 플로우입니다. |
| `workflow.id`      | 정수 | 플로우의 ID입니다. |
| `workflow.status`  | 문자열  | GitLab이 이벤트를 전송했을 때 플로우의 상태입니다. |
| `workflow.web_url` | 문자열  | GitLab의 플로우 세션 URL입니다. 그룹에서 실행된 플로우의 경우 생략됩니다. |

GitLab은 값이 없는 최상위 특성을 `null`로 전송하는 대신 생략합니다. `project` 및 `user` 객체에 중첩된 특성은 `null`일 수 있습니다.

`flow.failed` 페이로드는 `result` 객체 대신 `error` 객체를 포함합니다. 다음 예제는 `flow.completed`와 다른 특성만 표시합니다. GitLab은 또한 `project` 및 `user`도 전송합니다:

```json
{
  "object_kind": "duo_workflow",
  "version": "1",
  "event": "flow.failed",
  "event_id": "02affd2d-2cba-4033-917d-ec22d5dc4b38",
  "client_reference": "run-abc123",
  "error": {
    "reason": "flow_failed"
  },
  "workflow": {
    "id": 1,
    "status": "failed",
    "web_url": "https://gitlab.example.com/flightjs/Flight/-/automate/agent-sessions/1"
  }
}
```

이러한 이벤트의 배달 보장에 대해서는 [웹후크 콜백](../../duo_agent_platform/flows/webhook_callbacks.md#handling-callbacks-in-your-endpoint)을 참조하세요.
