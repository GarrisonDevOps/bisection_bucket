---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Bitbucket Cloud에서 마이그레이션
description: "Bitbucket Cloud에서 GitLab으로 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 일부 가져온 항목에서 **가져옴** 배지가 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/461210) GitLab 17.2에서.

{{< /history >}}

Bitbucket Cloud에서 GitLab으로 프로젝트를 가져옵니다.

Bitbucket Cloud 임포터는 Bitbucket Cloud에서 항목의 일부를 가져옵니다.

| Bitbucket Cloud 항목              | 가져옴 |
|:----------------------------------|:---------|
| 리포지토리 설명            | {{< yes >}} |
| Git 리포지토리 데이터               | {{< yes >}} |
| 이슈(댓글 포함)        | {{< yes >}} |
| 풀 요청(댓글 포함) | {{< yes >}} |
| 마일스톤                        | {{< yes >}} |
| 위키                              | {{< yes >}} |
| 레이블                            | {{< yes >}} |
| 마일스톤                        | {{< yes >}} |
| LFS 객체                       | {{< yes >}} |
| 마크다운의 인라인 이미지 및 첨부 파일 | {{< no >}} |
| 풀 요청 승인            | {{< no >}} |
| 승인 규칙                    | {{< no >}} |

## 알려진 이슈 {#known-issues}

- 이슈, 이슈 댓글 및 풀 요청에 포함된 이미지 및 파일 첨부 파일이 GitLab에 복사되지 않습니다. 원본 Bitbucket 호스팅 URL(예: `bitbucket.org` 또는 `bbuseruploads.s3.amazonaws.com`)을 가리키는 외부 링크로 남아 있습니다. 소스 Bitbucket 리포지토리가 삭제되면 포함된 모든 이미지 및 첨부 파일 링크가 영구적으로 손상됩니다. 소스 Bitbucket 리포지토리를 삭제하기 전에 포함된 모든 이미지 및 첨부 파일이 액세스 가능한지 확인하거나 따로 보관합니다. 이미지 및 첨부 파일 가져오기 지원이 [작업 항목 623235](https://gitlab.com/gitlab-org/gitlab/-/work_items/623235)에서 제안되었습니다.

## 임포터 워크플로우 {#importer-workflow}

Bitbucket Cloud 항목을 가져올 때:

- 풀 요청 및 이슈에 대한 참조가 유지됩니다.
- 리포지토리 공개 액세스는 유지됩니다. Bitbucket Cloud에서 리포지토리가 비공개인 경우 GitLab에서도 비공개로 생성됩니다.
- 가져온 이슈, 머지 리퀘스트 및 댓글에는 GitLab에서 **가져옴** 배지가 있습니다.

이슈, 풀 요청 및 댓글을 가져올 때 Bitbucket Cloud 임포터는 다음을 수행합니다:

- 작성자/할당자의 Bitbucket 닉네임을 사용하고 GitLab에서 동일한 Bitbucket ID를 찾으려고 시도합니다.
- 일치하지 않거나 GitLab 데이터베이스에서 사용자를 찾을 수 없는 경우 프로젝트 작성자(일반적으로 가져오기 프로세스를 시작한 현재 사용자)를 작성자로 설정하고 원본 Bitbucket 작성자에 대한 이슈의 참조를 유지합니다.

풀 요청의 경우 임포터는 다음을 수행합니다:

- 소스 SHA를 사용하고 리포지토리에 없으면 소스 커밋을 머지 커밋 SHA로 설정하려고 시도합니다.
- 머지 리퀘스트 할당자를 작성자로 설정하고 GitLab에서 Bitbucket ID와 일치하는 사용자 이름으로 검토자를 설정합니다.
- GitLab에서 머지 리퀘스트를 `opened`, `closed` 또는 `merged`로 설정합니다.

이슈의 경우 임포터는 다음을 수행합니다:

- Bitbucket의 이슈 유형에 해당하는 레이블을 추가합니다. `bug`, `enhancement`, `proposal` 또는 `task`입니다.
- Bitbucket의 이슈가 `resolved`, `invalid`, `duplicate`, `wontfix` 또는 `closed` 중 하나인 경우 GitLab에서 이슈를 닫습니다.

Bitbucket Cloud 임포터는 새 네임스페이스(그룹)가 없으면 생성합니다. 네임스페이스가 이미 사용 중인 경우 리포지토리는 가져오기 프로세스를 시작한 사용자의 네임스페이스로 가져옵니다.

## 사전 요구 사항 {#prerequisites}

- [Bitbucket Cloud 통합](../../integration/bitbucket.md)을 활성화하거나 GitLab 관리자에게 활성화를 요청해야 합니다. GitLab.com에서 기본적으로 활성화됨.
- [Bitbucket Cloud 임포트 소스](../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources)를 활성화하거나 GitLab 관리자에게 활성화를 요청해야 합니다. GitLab.com에서 기본적으로 활성화됨.
- 대상 그룹에서 가져올 유지 관리자 또는 소유자 역할이 있어야 합니다.
- Bitbucket의 풀 요청은 동일한 소스 및 대상 프로젝트를 가지고 있어야 하며 프로젝트의 포크에서 나올 수 없습니다. 그렇지 않으면 풀 요청이 빈 머지 리퀘스트로 가져옵니다.

사용자 기여도를 매핑하려면 각 사용자는 프로젝트 가져오기 전에 다음을 완료해야 합니다:

1. [Bitbucket 계정 설정](https://bitbucket.org/account/settings/)의 사용자 이름이 [Atlassian 계정 설정](https://id.atlassian.com/manage-profile/profile-and-visibility)의 공개 이름과 일치하는지 확인합니다. 일치하지 않으면 Atlassian 계정 설정의 공개 이름을 Bitbucket 계정 설정의 사용자 이름과 일치하도록 수정합니다.
1. [GitLab 프로필 서비스 로그인](https://gitlab.com/-/profile/account)에서 Bitbucket 계정을 연결합니다.

### Bitbucket Cloud API 토큰 생성 {#generate-a-bitbucket-cloud-api-token}

임포트 API를 사용하여 Bitbucket Cloud 리포지토리를 가져오려면 Bitbucket Cloud API 토큰을 생성해야 합니다.

Bitbucket Cloud API 토큰을 생성하려면:

1. <https://id.atlassian.com/manage-profile/security/api-tokens>로 이동합니다.
1. **범위를 사용하여 API 토큰 생성**을 선택합니다.
1. 토큰 이름과 만료 날짜를 입력한 다음 **다음**을 선택합니다.
1. **Bitbucket**을 선택한 다음 **다음**을 선택합니다.
1. 최소한 다음 범위를 선택합니다:

   - `read:repository:bitbucket`
   - `read:pullrequest:bitbucket`
   - `read:issue:bitbucket`
   - `read:wiki:bitbucket`

1. **토큰 생성**을 선택하고 토큰을 복사합니다.

## Bitbucket Cloud 리포지토리 가져오기 {#import-your-bitbucket-cloud-repositories}

1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **프로젝트 가져오기**를 선택합니다.
1. **Bitbucket Cloud**를 선택합니다.
1. Bitbucket에 로그인한 다음 **액세스 권한 부여**를 선택하여 GitLab에 Bitbucket 계정에 대한 액세스 권한을 부여합니다.
1. 가져올 프로젝트를 선택하거나 모든 프로젝트를 가져옵니다. 프로젝트를 이름으로 필터링하고 각 프로젝트를 가져올 네임스페이스를 선택할 수 있습니다.
1. 프로젝트를 가져오려면:
   - 처음에는 **가져오기**를 선택합니다.
   - 그 이후로는 **다시 가져오기**를 선택합니다. 새 이름을 지정하고 **다시 가져오기**를 다시 선택합니다. 다시 가져오기는 소스 프로젝트의 새 복사본을 생성합니다.

## 문제 해결 {#troubleshooting}

이 섹션에서는 Bitbucket Cloud에서 가져올 때 발생할 수 있는 문제에 대한 가능한 해결책을 포함합니다.

### 가져오기 프로세스에서 잘못된 계정 사용 {#import-process-used-wrong-account}

올바른 계정으로 로그인하는지 확인합니다. 잘못된 계정으로 가져오기 프로세스를 실수로 시작한 경우 다음 단계를 따릅니다:

1. Bitbucket 계정에 대한 GitLab 액세스를 취소하여 [Bitbucket Cloud 리포지토리를 가져올](#import-your-bitbucket-cloud-repositories) 때 프로세스를 기본적으로 되돌립니다.
1. Bitbucket 계정에서 로그아웃한 다음 [Bitbucket Cloud 리포지토리를 가져오기](#import-your-bitbucket-cloud-repositories)를 다시 수행합니다.

### 이름이 일치해도 사용자 매핑이 실패 {#user-mapping-fails-despite-matching-names}

[사용자 매핑이 작동](mapping/post_migration_mapping.md)하려면 Bitbucket 계정 설정의 사용자 이름이 Atlassian 계정 설정의 공개 이름과 일치해야 합니다.

이 이름이 일치하지만 사용자 매핑이 여전히 실패하면 [GitLab 프로필 서비스 로그인](https://gitlab.com/-/profile/account)에서 Bitbucket 계정을 연결한 후 사용자가 Bitbucket 사용자 이름을 수정했을 수 있습니다.

이 문제를 해결하려면 사용자는 GitLab 데이터베이스의 Bitbucket 외부 UID가 현재 Bitbucket 공개 이름과 일치하는지 확인하고 불일치가 있으면 다시 연결해야 합니다:

1. [인증된 사용자를 얻기 위해 API 사용](../../api/users.md#retrieve-the-current-user)합니다.
1. API 응답에서 `identities` 속성에는 GitLab 데이터베이스에 있는 Bitbucket 계정이 포함됩니다. `extern_uid`가 현재 Bitbucket 공개 이름과 일치하지 않으면 사용자는 [GitLab 프로필 서비스 로그인](https://gitlab.com/-/profile/account)에서 Bitbucket 계정을 다시 연결해야 합니다.
1. 다시 연결한 후 사용자는 API를 다시 사용하여 GitLab 데이터베이스의 `extern_uid`가 현재 Bitbucket 공개 이름과 일치하는지 확인해야 합니다.

프로젝트를 가져온 사용자는 [가져온 프로젝트 삭제](../project/working_with_projects.md#delete-a-project)한 다음 다시 가져와야 합니다.

## 관련 항목 {#related-topics}

- [Bitbucket Server에서 마이그레이션](bitbucket_server.md)
- [API 가져오기](../../api/import.md)
- [가져오기 및 내보내기 설정](../../administration/settings/import_and_export_settings.md).
- [가져오기를 위한 Sidekiq 구성](../../administration/sidekiq/configuration_for_imports.md).
- [여러 Sidekiq 프로세스 실행](../../administration/sidekiq/extra_sidekiq_processes.md).
- [특정 작업 클래스 처리](../../administration/sidekiq/processing_specific_job_classes.md).
