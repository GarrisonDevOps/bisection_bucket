---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Bitbucket Server에서 마이그레이션
description: "Bitbucket Server에서 GitLab로 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/153041) GitLab 17.1에서 이메일 주소로만 사용자를 매핑하도록.
- 일부 가져온 항목에서 **가져옴** 배지가 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/461211) GitLab 17.2에서.
- [GitLab.com에서 변경됨](https://gitlab.com/groups/gitlab-org/-/work_items/14667) [마이그레이션 후 사용자 기여 및 멤버십 매핑](mapping/post_migration_mapping.md)으로 GitLab 17.8에서.
- 마이그레이션 후 사용자 및 기여 멤버십 매핑이 [GitLab.com 및 GitLab Self-Managed에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/176675) GitLab 17.8에서.

{{< /history >}}

Bitbucket Server에서 GitLab으로 프로젝트를 가져옵니다.

Bitbucket Server 임포터는 Bitbucket Server의 항목 부분 집합을 가져옵니다.

| Bitbucket Server 항목                                                         | 가져옴 |
|:------------------------------------------------------------------------------|:---------|
| 리포지토리 설명                                                        | {{< yes >}} |
| Git 리포지토리 데이터                                                           | {{< yes >}} |
| 풀 요청(댓글, 사용자 멘션, 검토자, 병합 이벤트 포함) | {{< yes >}} |
| LFS 객체                                                                   | {{< yes >}} |
| 코드에 대한 댓글[^doesn-allow-comments]                                                  | {{< yes >}} |
| 스레드[^multiple-threading-levels]                                                           | {{< yes >}} |
| 프로젝트 필터[^project-filtering-doesn]                                                   | {{< yes >}} |
| Markdown의 첨부 파일                                                       | {{< no >}} |
| 작업 목록                                                                    | {{< no >}} |
| 이모지 반응                                                               | {{< no >}} |
| 풀 요청 승인                                                        | {{< no >}} |
| 풀 요청에 대한 승인 규칙                                              | {{< no >}} |

[^doesn-allow-comments]: GitLab은 코드의 임의의 라인에 댓글을 달 수 없습니다. 범위를 벗어난 Bitbucket 댓글은 머지 리퀘스트의 댓글로 삽입됩니다.
[^multiple-threading-levels]: 여러 스레딩 수준이 하나의 스레드로 축소되고 인용문이 원본 댓글의 일부로 추가됩니다.
[^project-filtering-doesn]: 프로젝트 필터는 유사 검색을 지원하지 않습니다. 시작 문자열 또는 전체 일치 문자열만 지원됩니다.

## 알려진 이슈 {#known-issues}

- 풀 요청 설명 및 댓글에 포함된 이미지 및 파일 첨부 파일은 GitLab으로 복사되지 않습니다. 원래 Bitbucket 호스팅 URL을 가리키는 외부 링크로 남아 있습니다. 원본 Bitbucket Server 인스턴스가 폐기되거나 리포지토리가 삭제되면 포함된 모든 이미지 및 첨부 파일 링크가 영구적으로 끊어집니다. 원본 Bitbucket Server 인스턴스를 폐기하기 전에 포함된 모든 이미지 및 첨부 파일에 액세스할 수 있는지 확인하거나 별도로 보존하세요. 이미지 및 첨부 파일 가져오기 지원이 [작업 항목 623235](https://gitlab.com/gitlab-org/gitlab/-/work_items/623235)에서 제안되었습니다.

## 임포터 워크플로우 {#importer-workflow}

Bitbucket Server 임포터는 GitLab.com 및 GitLab Self-Managed용 사용자 기여의 [마이그레이션 후 매핑](mapping/post_migration_mapping.md)을 지원합니다. 임포터는 매핑의 [대체 방법](#alternative-method-of-mapping)도 지원합니다.

Bitbucket Server 항목을 가져올 때:

- 리포지토리 공개 액세스는 유지됩니다. Bitbucket에서 리포지토리가 비공개이면 GitLab에서도 비공개로 생성됩니다.
- 가져온 머지 리퀘스트 및 댓글에는 GitLab에서 **가져옴** 배지가 있습니다.

폐기되거나 병합된 풀 요청을 가져올 때, 리포지토리에 없는 커밋 SHA는 Bitbucket Server에서 가져와서 풀 요청에 커밋이 연결되어 있는지 확인합니다:

- 소스 커밋 SHA는 `refs/merge-requests/<iid>/head` 형식의 참조로 저장됩니다.
- 대상 커밋 SHA는 `refs/keep-around/<SHA>` 형식의 참조로 저장됩니다.

소스 커밋이 리포지토리에 없으면 커밋 메시지에 SHA가 포함된 커밋이 대신 사용됩니다.

## 가져오기 기간 추정 {#estimating-import-duration}

Bitbucket Server에서의 모든 가져오기는 다르므로 수행하는 가져오기의 기간에 영향을 미칩니다. 그러나 가져오기 기간을 추정하는 데 도움이 되도록, 다음 데이터로 구성된 프로젝트는 가져오는 데 8시간이 걸릴 가능성이 높습니다:

- 13,000개의 풀 요청
- 7,000개의 태그
- 500GiB 리포지토리

## 사전 요구 사항 {#prerequisites}

- Bitbucket Server는 GitLab 인스턴스에서 액세스할 수 있어야 합니다. Bitbucket Server URL은 공개적으로 확인할 수 있거나 GitLab이 실행 중인 네트워크에서 액세스할 수 있어야 합니다.
- [Bitbucket Server 가져오기 소스](../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources)를 활성화하거나 GitLab 관리자에게 활성화를 요청해야 합니다. GitLab.com에서 기본적으로 활성화됨.
- 가져올 대상 그룹에 대한 유지 관리자 또는 소유자 역할.
- 관리자 액세스 권한이 있는 Bitbucket Server 인증 토큰. 관리자 액세스 권한이 없으면 일부 데이터는 [가져오지 않습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/446218).

## Bitbucket Server 리포지토리 가져오기 {#import-your-bitbucket-server-repositories}

Bitbucket Server 리포지토리를 가져오려면:

1. GitLab에 로그인합니다.
1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **프로젝트 가져오기**를 선택합니다.
1. **Bitbucket Server**를 선택합니다.
1. Bitbucket에 로그인하고 GitLab에 Bitbucket 계정에 대한 액세스 권한을 부여합니다.
1. 가져올 프로젝트를 선택하거나 모든 프로젝트를 가져옵니다. 이름으로 프로젝트를 필터링하고 각 프로젝트를 가져올 네임스페이스를 선택할 수 있습니다.
1. 프로젝트를 가져오려면:
   - 처음에는 **가져오기**를 선택합니다.
   - 그 이후로는 **다시 가져오기**를 선택합니다. 새 이름을 지정하고 **다시 가져오기**를 다시 선택합니다. 다시 가져오기는 소스 프로젝트의 새 복사본을 생성합니다.

## 매핑의 대체 방법 {#alternative-method-of-mapping}

`bitbucket_server_user_mapping` 기능 플래그를 비활성화하여 가져오기에 대한 대체 사용자 기여 매핑 방법을 사용할 수 있습니다.

GitLab.com으로 가져오려면 [마이그레이션 후 방법](mapping/post_migration_mapping.md)을 대신 사용해야 합니다.

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 이 기능은 권장되지 않으며 GitLab.com으로의 마이그레이션에는 사용할 수 없습니다. 이 매핑 방법에서 발견된 문제는 수정될 가능성이 낮습니다. 이러한 제한 사항이 없는 [마이그레이션 후 방법](mapping/post_migration_mapping.md)을 대신 사용하세요.
>
> 자세한 내용은 [이슈 512213](https://gitlab.com/gitlab-org/gitlab/-/work_items/512213)을 참조하세요.

대체 방법을 사용하면 임포터는 Bitbucket Server 사용자의 이메일 주소를 GitLab 사용자 데이터베이스의 확인된 이메일 주소와 일치시키려고 합니다. 그러한 사용자를 찾지 못한 경우:

- 프로젝트 작성자가 대신 사용됩니다. 임포터는 원본 작성자를 표시하기 위해 댓글에 메모를 추가합니다.
- 풀 요청 검토자의 경우 검토자가 할당되지 않습니다.
- 풀 요청 승인자의 경우 승인이 추가되지 않습니다.

풀 요청 설명 및 메모의 멘션은 사용자의 이메일 주소를 사용하여 Bitbucket Server의 사용자 프로필과 일치합니다. GitLab에서 동일한 이메일 주소를 가진 사용자를 찾지 못하면 멘션이 정적으로 변환됩니다. 사용자가 일치되려면 프로젝트에 대한 최소 읽기 액세스 권한을 제공하는 GitLab 역할이 있어야 합니다.

프로젝트가 공개이면 GitLab은 프로젝트에 초대된 사용자만 일치합니다.

임포터는 새 네임스페이스(그룹)가 없으면 생성합니다. 네임스페이스가 사용 중인 경우, 리포지토리는 가져오기 프로세스를 시작한 사용자의 네임스페이스 아래로 가져옵니다.

## 문제 해결 {#troubleshooting}

다음 섹션에는 발생할 수 있는 문제에 대한 해결책이 포함되어 있습니다.

### 일반 {#general}

GUI 기반 가져오기 도구가 작동하지 않으면 다음을 시도할 수 있습니다:

- [가져오기 API](../../api/import.md#import-repository-from-bitbucket-server) Bitbucket Server 엔드포인트를 사용합니다.
- [리포지토리 미러링](../project/repository/mirror/_index.md)을 설정합니다. 상세한 오류 출력을 제공합니다.

Bitbucket Cloud의 [문제 해결 섹션](bitbucket_cloud.md#troubleshooting)을 참조하세요.

### LFS 객체를 가져오지 않음 {#lfs-objects-not-imported}

프로젝트 가져오기가 완료되었지만 LFS 객체를 다운로드하거나 복제할 수 없으면 특수 문자가 포함된 암호 또는 개인 액세스 토큰을 사용할 수 있습니다. 자세한 내용은 [이슈 337769](https://gitlab.com/gitlab-org/gitlab/-/issues/337769)를 참조하세요.

### 잘못된/해석할 수 없는 호스트 주소로 인해 가져오기 실패 또는 가져오기 URL이 차단됨 {#import-fails-due-to-invalidunresolved-host-address-or-the-import-url-is-blocked}

프로젝트 가져오기가 `Importing the project failed: Import URL is blocked`과(와) 같은 오류 메시지로 실패하면 Bitbucket 서버로의 초기 연결이 성공했음에도 불구하고 Bitbucket 서버 또는 역방향 프록시가 제대로 구성되지 않았을 수 있습니다.

이 문제를 해결하려면 [Projects API](../../api/projects.md)를 사용하여 새로 생성된 프로젝트를 확인하고 프로젝트의 `import_url` 값을 찾습니다.

이 값은 가져오기에 사용할 Bitbucket 서버에서 제공한 URL을 나타냅니다. 이 URL을 공개적으로 확인할 수 없으면 해석할 수 없는 주소 오류가 발생할 수 있습니다.

이 문제를 해결하려면 Bitbucket 서버가 프록시 서버를 인식하고 있는지 확인하세요. 프록시 서버는 Bitbucket이 URL을 구성하고 사용하는 방식에 영향을 미칠 수 있기 때문입니다. 자세한 내용은 [프록시 및 보안 Bitbucket](https://confluence.atlassian.com/bitbucketserver/proxy-and-secure-bitbucket-776640099.html)을 참조하세요.

### JSON::NestingError로 인해 가져오기 실패 {#import-fails-with-jsonnestingerror}

프로젝트 가져오기가 `JSON::NestingError`을(를) 포함하는 오류 메시지로 실패하면 Bitbucket Server 응답에 `max_http_response_json_depth` 설정을 초과하는 깊게 중첩된 객체가 포함됩니다.

이 문제를 해결하려면 [아웃바운드 요청의 JSON HTTP 응답에서 허용되는 최대 중첩 깊이](../../administration/instance_limits.md#maximum-allowed-nesting-depth-in-json-http-responses-from-outbound-requests)를 늘립니다.

## 관련 항목 {#related-topics}

- [Bitbucket Cloud에서 마이그레이션](bitbucket_cloud.md).
- [가져오기 및 내보내기 설정](../../administration/settings/import_and_export_settings.md).
- [가져오기를 위한 Sidekiq 구성](../../administration/sidekiq/configuration_for_imports.md).
- [여러 Sidekiq 프로세스 실행](../../administration/sidekiq/extra_sidekiq_processes.md).
- [특정 작업 클래스 처리](../../administration/sidekiq/processing_specific_job_classes.md).
