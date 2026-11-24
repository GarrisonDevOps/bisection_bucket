---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 파일 내보내기를 사용하여 GitLab 데이터 마이그레이션
description: "파일 내보내기를 사용하여 GitLab 데이터를 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 마일스톤 제목을 이름 바꾸어 대상 인스턴스의 충돌을 방지 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/221447) GitLab 18.6.7 이상, 18.7.5 이상 및 18.8.5 이상.

{{< /history >}}

파일 내보내기는 오프라인 환경에서 작동하는 GitLab 데이터의 휴대용 패키지를 제공합니다. 이 마이그레이션 방법은 리포지토리, 이슈, 머지 리퀘스트, 댓글을 포함한 대부분의 프로젝트 데이터를 보존합니다.

파일 내보내기를 사용하여:

- 오프라인 환경 간에 마이그레이션합니다.
- 전체 그룹 구조 없이 특정 프로젝트를 이동합니다.

[직접 전송](../../group/import/_index.md)은 대부분의 상황에 권장되는 마이그레이션 방법입니다.

> [!note]
> 데이터를 백업하기 위해 프로젝트 내보내기 파일을 사용하지 않아야 합니다. 프로젝트 내보내기 파일을 백업에 사용하는 것이 항상 작동하지는 않으며 모든 항목이 내보내지는 것은 아닙니다.

## 알려진 이슈 {#known-issues}

- 알려진 문제로 인해 `PG::QueryCanceled: ERROR: canceling statement due to statement timeout` 오류가 발생할 수 있습니다. 자세한 내용은 [문제 해결 설명서](import_export_troubleshooting.md#error-pgquerycanceled-error-canceling-statement-due-to-statement-timeout)를 참조하세요.
- GitLab 17.0, 17.1 및 17.2에서는 가져온 에픽과 작업 항목이 원래 작성자가 아닌 가져오기를 수행한 사용자에게 매핑됩니다.
- 머지 리퀘스트의 경우 가져오기 또는 내보내기 중에 최신 diff만 보존됩니다. 프로젝트를 가져오거나 내보낸 후 머지 리퀘스트의 최신 diff 버전과 최신 파이프라인만 표시됩니다.
- 대상 네임스페이스 내에 [기존 마일스톤과 일치하는](../milestones/_index.md#milestone-title-rules) 제목을 가진 가져온 마일스톤은 가져오기 시 제목이 업데이트됩니다. 새 제목에는 고유한 접미사가 추가됩니다. 예를 들어 `18.0`는 `18.0
  (imported-3d-1770206299)`이 됩니다. 이를 피하려면 직접 전송을 시작하기 전에 원본 그룹 또는 프로젝트의 마일스톤 이름을 바꿉니다.

## 내보내기 파일을 업로드하여 프로젝트 마이그레이션 {#migrate-projects-by-uploading-an-export-file}

기존 프로젝트를 파일로 내보낸 다음 다른 GitLab 인스턴스로 가져올 수 있습니다.

### 사용자 기여 보존 {#preserving-user-contributions}

사용자 기여를 보존하기 위한 요구 사항은 GitLab.com으로 마이그레이션하는지 아니면 GitLab Self-Managed 인스턴스로 마이그레이션하는지에 따라 달라집니다.

#### GitLab Self-Managed에서 GitLab.com으로 마이그레이션할 때 {#when-migrating-from-gitlab-self-managed-to-gitlabcom}

파일 내보내기를 사용하여 프로젝트를 마이그레이션할 때 사용자 기여가 올바르게 매핑되려면 관리자의 액세스 토큰이 필요합니다.

따라서 GitLab Self-Managed 인스턴스에서 GitLab.com으로 파일 내보내기를 가져올 때 사용자 기여가 올바르게 매핑되지 않습니다. 대신 모든 GitLab 사용자 연결(예: 댓글 작성자)이 프로젝트를 가져오는 사용자로 변경됩니다. 기여 기록을 보존하려면 다음 중 하나를 수행하세요:

- [직접 전송을 사용하여 마이그레이션합니다](../../group/import/_index.md).
- 전문 서비스 이용을 고려하세요. 자세한 내용은 [전문 서비스 카탈로그](https://about.gitlab.com/professional-services/catalog/)를 참조하세요.

#### GitLab Self-Managed로 마이그레이션할 때 {#when-migrating-to-gitlab-self-managed}

GitLab이 사용자 및 해당 기여를 올바르게 매핑하도록 하려면:

- 프로젝트의 최상위 그룹 소유자가 프로젝트를 내보내야 하므로 프로젝트에 액세스할 수 있는 모든 구성원(직접 및 상속)의 정보를 내보낸 파일에 포함할 수 있습니다. 프로젝트 유지관리자 및 소유자는 프로젝트 내보내기를 시작할 수 있습니다. 그러나 프로젝트의 직접 구성원만 내보내집니다.
- 관리자가 가져오기를 수행해야 합니다.
- 필수 사용자가 대상 GitLab 인스턴스에 존재해야 합니다. 관리자는 Rails 콘솔에서 대량으로 또는 UI에서 하나씩 확인된 사용자를 만들 수 있습니다.
- 사용자는 원본 GitLab 인스턴스의 프로필에서 [공개 이메일을 설정](../../profile/_index.md#set-your-public-email)하여 대상 GitLab 인스턴스의 기본 이메일 주소와 일치해야 합니다. [프로젝트 내보내기 파일을 편집](#edit-project-export-files)하여 사용자의 공개 이메일을 수동으로 추가할 수도 있습니다.
- [GitLab 18.4 이상에서](https://gitlab.com/gitlab-org/gitlab/-/issues/559224) 프로젝트를 기존 그룹으로 직접 가져올 때 직접 구성원 자격을 만들면 [**이 그룹의 프로젝트에 사용자를 추가할 수 없습니다.** 설정](../../group/access_and_permissions.md#prevent-members-from-being-added-to-projects-in-a-group)이 존중됩니다.

기존 사용자의 이메일이 가져온 사용자의 이메일과 일치하면 해당 사용자가 [직접 구성원](../members/_index.md)으로 가져온 프로젝트에 추가됩니다.

이전 조건 중 하나라도 충족되지 않으면 사용자 기여가 올바르게 매핑되지 않습니다. 대신 모든 GitLab 사용자 연결이 가져오기를 수행한 사용자로 변경됩니다. 해당 사용자는 다른 사용자가 만든 머지 리퀘스트의 작성자가 됩니다. 원래 작성자를 언급하는 추가 댓글은:

- 댓글, 머지 리퀘스트 승인, 연결된 작업 및 항목에 추가됩니다.
- 머지 리퀘스트 또는 이슈 작성자, 추가 또는 제거된 레이블 및 병합 정보에는 추가되지 않습니다.

### 프로젝트 내보내기 파일 편집 {#edit-project-export-files}

내보내기 파일에서 데이터를 추가하거나 제거할 수 있습니다. 예를 들어 다음을 수행할 수 있습니다:

- 사용자의 공개 이메일을 `project_members.ndjson` 파일에 수동으로 추가합니다.
- `ci_pipelines.ndjson` 파일에서 줄을 제거하여 CI 파이프라인을 자릅니다.

프로젝트 내보내기 파일을 편집하려면:

1. 내보낸 `.tar.gz` 파일을 추출합니다.
1. 적절한 파일을 편집합니다. 예를 들어, `tree/project/project_members.ndjson`입니다.
1. 파일을 `.tar.gz` 파일로 다시 압축합니다.

`project_members.ndjson` 파일을 확인하여 모든 구성원이 내보내졌는지 확인할 수도 있습니다.

### 호환성 {#compatibility}

프로젝트 파일 내보내기는 NDJSON 형식입니다.

GitLab 최대 2개 [마이너](../../../policy/maintenance.md#versioning) 버전 이전 버전에서 내보낸 프로젝트 파일 내보내기를 가져올 수 있습니다.

예를 들어:

| 대상 버전 | 호환 가능한 원본 버전 |
|:--------------------|:---------------------------|
| 13.0                | 13.0, 12.10, 12.9          |
| 13.1                | 13.1, 13.0, 12.10          |

### 가져오기 원본으로 파일 내보내기 구성 {#configure-file-exports-as-an-import-source}

{{< details >}}

- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Self-Managed에서 파일 내보내기를 사용하여 프로젝트를 마이그레이션하기 전에 GitLab 관리자는 다음을 수행해야 합니다:

1. 원본 인스턴스에서 [파일 내보내기를 활성화](../../../administration/settings/import_and_export_settings.md#enable-project-export)합니다.
1. 대상 인스턴스에 대한 가져오기 원본으로 파일 내보내기를 활성화합니다. GitLab.com에서는 파일 내보내기가 이미 가져오기 원본으로 활성화되어 있습니다.

대상 인스턴스에 대한 가져오기 원본으로 파일 내보내기를 활성화하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **가져오기 및 내보내기 설정**을 확장합니다.
1. **소스 가져오기**로 스크롤합니다.
1. **GitLab 내보내기** 확인란을 선택합니다.

### CE와 EE 간 {#between-ce-and-ee}

[호환성](#compatibility)이 충족되는 경우 Community Edition에서 Enterprise Edition으로 프로젝트를 내보낼 수 있으며 그 반대도 가능합니다.

Enterprise Edition에서 Community Edition으로 프로젝트를 내보내는 경우 Enterprise Edition에서만 보존되는 데이터가 손실될 수 있습니다. 자세한 내용은 [EE에서 CE로 되돌리기](../../../update/convert_to_ee/revert.md)를 참조하세요.

### 프로젝트 및 해당 데이터 내보내기 {#export-a-project-and-its-data}

프로젝트를 가져오기 전에 먼저 내보내야 합니다.

사전 요구 사항:

- [내보낸 항목](#project-items-that-are-exported) 목록을 검토합니다. 모든 항목이 내보내지는 것은 아닙니다.
- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 많은 수의 Git 참조를 포함한 리포지토리의 성능을 크게 향상시키려면 GitLab 18.0 이상을 사용하세요. 자세한 내용은 [GitLab 리포지토리 백업 시간 단축에 대한 블로그 게시물](https://about.gitlab.com/blog/how-we-decreased-gitlab-repo-backup-times-from-48-hours-to-41-minutes/)을 참조하세요.

프로젝트 및 해당 데이터를 내보내려면 다음 단계를 따릅니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급**을 확장합니다.
1. **프로젝트 내보내기**를 선택합니다.
1. 내보내기가 생성된 후 다음을 수행할 수 있습니다:
   - 받아야 하는 이메일에 포함된 링크를 따릅니다.
   - 프로젝트 설정 페이지를 새로 고친 다음 **프로젝트 내보내기** 영역에서 **내보내기 다운로드**를 선택합니다.

내보내기는 구성된 `shared_path`, 임시 공유 디렉터리(기본값: `<shared_path>/tmp/gitlab_exports`)에서 생성된 다음 다음 중 하나로 이동합니다:

- 구성된 `uploads_directory`로 이동합니다.
- 객체 저장소에 업로드됩니다.

24시간마다 워커가 이러한 내보내기 파일을 삭제합니다.

별도의 Sidekiq, Gitaly 및 GitLab 애플리케이션(Rails) 노드가 있는 GitLab 인스턴스에서는 [`shared_path`](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/b350e3cd5b06a94adb463ece4d41b9f3df6ab282/files/gitlab-config-template/gitlab.rb.template#L731) 설정에 지정된 디렉터리를 모든 노드에서 사용할 수 있어야 합니다.

#### 내보낸 프로젝트 항목 {#project-items-that-are-exported}

내보낸 프로젝트 항목은 사용하는 GitLab 버전에 따라 달라집니다. 특정 프로젝트 항목이 내보내지는지 확인하려면:

1. [`exporters` 배열](https://gitlab.com/gitlab-org/gitlab/-/blob/b819a6aa6d53573980dd9ee4a1bfe597d69e88e5/app/services/projects/import_export/export_service.rb#L24)을 확인합니다.
1. GitLab 버전에 대한 [`project/import_export.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/import_export/project/import_export.yml) 파일을 확인합니다. 예를 들어 GitLab 19.2의 경우 <https://gitlab.com/gitlab-org/gitlab/-/blob/19-2-stable-ee/lib/gitlab/import_export/project/import_export.yml>입니다.

빠른 개요를 위해 내보낸 항목에는 다음이 포함됩니다:

- 프로젝트 및 wiki 리포지토리
- 프로젝트 업로드
- 통합을 제외한 프로젝트 구성
- 이슈
  - 이슈 댓글
  - 이슈 반복
  - 이슈 리소스 상태 이벤트
  - 이슈 리소스 마일스톤 이벤트
  - 이슈 리소스 반복 이벤트
- 머지 리퀘스트
  - 머지 리퀘스트 diff
  - 머지 리퀘스트 댓글
  - 머지 리퀘스트 리소스 상태 이벤트
  - 머지 리퀘스트 여러 담당자
  - 머지 리퀘스트 검토자
  - 머지 리퀘스트 승인자
- 커밋 댓글
- 레이블
- 마일스톤
- 스니펫
- 릴리스
- 시간 추적 및 기타 프로젝트 엔터티
- 설계 관리 파일 및 데이터
- LFS 객체
- 이슈 보드
- CI/CD 파이프라인(보관됨)
- 파이프라인 일정(비활성 및 가져오기를 시작한 사용자에게 할당됨)
- 보호된 브랜치 및 태그
- 푸시 규칙
- 이모지 반응

  > [!note]
  > 사용자 지정 이모지를 사용하는 이모지 반응은 대상에 동일한 이름의 사용자 지정 이모지가 존재하는 경우에만 가져옵니다. 대상에서 누락된 사용자 지정 이모지를 참조하는 반응은 건너뜁니다.

- 직접 프로젝트 구성원(내보낸 프로젝트의 그룹에 대한 유지관리자 또는 소유자 역할이 있는 경우)
- 직접 프로젝트 구성원으로서의 상속된 프로젝트 구성원(내보낸 프로젝트의 그룹에 대한 소유자 역할 또는 인스턴스에 대한 관리자 액세스 권한이 있는 경우)
- 일부 머지 리퀘스트 승인 규칙:
  - [보호된 브랜치에 대한 승인](../merge_requests/approvals/rules.md#approvals-for-protected-branches)
  - [적격 승인자](../merge_requests/approvals/rules.md#eligible-approvers)
- 취약성 보고서([GitLab 17.7에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/501466))

#### 내보내지지 않은 프로젝트 항목 {#project-items-that-are-not-exported}

내보내지지 않은 항목에는 다음이 포함됩니다:

- [자식 파이프라인 기록](https://gitlab.com/gitlab-org/gitlab/-/issues/221088)
- 파이프라인 트리거
- CI/CD 작업 추적 및 아티팩트
- 패키지 및 컨테이너 레지스트리 이미지
- CI/CD 변수
- CI/CD 작업 토큰 허용 목록
- 웹후크
- 암호화된 토큰
- [필수 승인 수](https://gitlab.com/gitlab-org/gitlab/-/issues/221087)
- 리포지토리 크기 제한
- 보호된 브랜치로 푸시할 수 있는 배포 키
- 보안 파일
- [Git 관련 이벤트에 대한 활동 로그](https://gitlab.com/gitlab-org/gitlab/-/issues/214700)(예: 푸시 및 태그 생성)
- 프로젝트와 연결된 보안 정책
- 이슈와 연결된 항목 간의 링크
- 관련 머지 리퀘스트로의 링크
- 파이프라인 일정 변수

### 프로젝트 및 해당 데이터 가져오기 {#import-a-project-and-its-data}

{{< history >}}

- [GitLab 19.5에서 변경되어](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256551) 원본 프로젝트의 생성 날짜를 보존합니다.

{{< /history >}}

프로젝트 및 해당 데이터를 가져올 수 있습니다. 가져올 수 있는 데이터의 양은 최대 가져오기 파일 크기에 따라 달라집니다:

- GitLab Self-Managed에서 관리자는 [최대 가져오기 파일 크기를 설정](#set-maximum-import-file-size)할 수 있습니다.
- GitLab.com에서 값은 [5GB로 설정됩니다](../../gitlab_com/_index.md#account-and-limit-settings).

> [!warning]
> 신뢰하는 출처에서만 프로젝트를 가져옵니다. 신뢰할 수 없는 출처에서 프로젝트를 가져오는 경우 공격자가 민감한 데이터를 도용할 수 있습니다.

#### 사전 요구 사항 {#prerequisites}

- [프로젝트 및 해당 데이터를 내보내야](#export-a-project-and-its-data) 합니다.
- GitLab 버전을 비교하고 내보낸 GitLab 버전과 동일하거나 그 이상인 GitLab 버전으로 가져오는지 확인합니다.
- 문제가 있는지 [호환성](#compatibility)을 검토합니다.
- 마이그레이션할 대상 그룹의 유지관리자 또는 소유자 역할입니다.
- `tar` 명령은 원본 및 대상 GitLab 인스턴스 모두에 설치되어야 합니다.

#### 프로젝트 가져오기 {#import-a-project}

프로젝트를 가져오려면:

1. 오른쪽 상단 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 그리고 **새 프로젝트/리포지토리**를 선택합니다.
1. **프로젝트 가져오기**를 선택합니다.
1. **프로젝트 가져오기**에서 **GitLab 내보내기**를 선택합니다.
1. 프로젝트 이름 및 URL을 입력합니다. 그런 다음 이전에 내보낸 파일을 선택합니다.
1. **프로젝트 가져오기**를 선택합니다.

[API](../../../api/project_import_export.md#retrieve-the-status-of-a-project-import)를 사용하여 가져오기 상태를 쿼리할 수 있습니다. 쿼리에서 가져오기 오류 또는 예외가 반환될 수 있습니다.

#### 가져온 항목의 변경 사항 {#changes-to-imported-items}

내보낸 항목은 다음과 같은 변경 사항으로 가져옵니다:

- 소유자 역할을 가진 프로젝트 구성원은 유지관리자 역할로 가져옵니다.
- 가져온 프로젝트에 포크에서 시작된 머지 리퀘스트가 포함되어 있으면 이러한 머지 리퀘스트와 연결된 새 브랜치가 프로젝트에서 생성됩니다. 따라서 새 프로젝트의 브랜치 수가 원본 프로젝트보다 많을 수 있습니다.
- `Internal` 가시성 수준이 [제한되면](../../public_access.md#restrict-use-of-public-or-internal-projects) 모든 가져온 프로젝트에 `Private` 가시성이 지정됩니다.
- 보호된 브랜치 및 보호된 태그 액세스 수준이 유지관리자로 재설정됩니다. 예를 들어 **머지 허용**이 **개발자 + 유지관리자**로 설정되면 **유지관리자**가 됩니다. "아무도 아님"으로 설정된 액세스 수준은 보존됩니다.
  - 원래 액세스 수준을 보존하려면 가져오기를 수행하는 사용자가 대상 프로젝트의 최상위 그룹에 대한 소유자 역할을 가지고 있거나 GitLab 관리자여야 합니다.
  - 대상 프로젝트가 개인 네임스페이스에 있으면 액세스 수준이 항상 재설정됩니다.

배포 키는 가져오지 않습니다. 배포 키를 사용하려면 가져온 프로젝트에서 해당 키를 활성화하고 보호된 브랜치를 업데이트해야 합니다.

> [!warning]
> 머지 리퀘스트에 대한 가져온 파이프라인은 원본 상태를 유지하며 다시 실행하지 않고도 **파이프라인이 성공해야 함** 및 [보안 정책 파이프라인 확인](../../application_security/policies/pipeline_execution_policies.md#security-policy-pipeline-check)을 대상 인스턴스에서 만족할 수 있습니다. 병합하기 전에 가져온 머지 리퀘스트에서 새 파이프라인을 실행합니다.

#### 대규모 프로젝트 가져오기 {#import-large-projects}

{{< details >}}

- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

더 큰 프로젝트가 있다면 [Rake 작업 사용](../../../administration/raketasks/project_import_export.md#import-large-projects)을 고려합니다.

### 최대 가져오기 파일 크기 설정 {#set-maximum-import-file-size}

{{< details >}}

- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

관리자는 두 가지 방법 중 하나로 최대 가져오기 파일 크기를 설정할 수 있습니다:

- [애플리케이션 설정 API](../../../api/settings.md#update-application-settings)에서 `max_import_size` 옵션을 사용하여.
- [**운영자** 영역 UI](../../../administration/settings/import_and_export_settings.md#max-import-size)에서.

기본값은 `0`(무제한)입니다.

### 속도 제한 {#rate-limits}

남용을 방지하기 위해 기본적으로 사용자는 다음으로 속도 제한됩니다:

| 요청 유형    | 한도                           |
|:----------------|:--------------------------------|
| 내보내기          | 분당 6개 프로젝트           |
| 내보내기 다운로드 | 프로젝트당 분당 1회 다운로드 |
| 가져오기          | 분당 6개 프로젝트           |

## 내보내기 파일을 업로드하여 그룹 마이그레이션(더 이상 사용되지 않음) {#migrate-groups-by-uploading-an-export-file-deprecated}

{{< history >}}

- GitLab 14.6에서 [더 이상 사용되지 않습니다](https://gitlab.com/groups/gitlab-org/-/work_items/4619).
- GitLab 19.5에서 [변경되어](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256551) 원본 그룹의 생성 날짜를 보존합니다.

{{< /history >}}

> [!warning]
> 이 기능은 GitLab 14.6에서 [더 이상 사용되지 않으며](https://gitlab.com/groups/gitlab-org/-/work_items/4619) [그룹을 직접 전송으로 마이그레이션](../../group/import/_index.md)하기로 대체되었습니다. 그러나 이 기능은 [오프라인 환경](../../application_security/offline_deployments/_index.md)의 마이그레이션에 권장됩니다. 오프라인 인스턴스 간 마이그레이션 지원은 [에픽 8985](https://gitlab.com/groups/gitlab-org/-/work_items/8985)에서 제안됩니다.

사전 요구 사항:

- 마이그레이션할 그룹의 소유자 역할입니다.

파일 내보내기를 사용하면 다음을 수행할 수 있습니다:

- 그룹을 파일로 내보낸 다음 해당 파일을 다른 GitLab 인스턴스 또는 동일한 인스턴스의 다른 위치로 업로드합니다.
- GitLab UI 또는 [API](../../../api/group_import_export.md)를 사용합니다.
- 그룹을 하나씩 마이그레이션한 다음 각 그룹의 각 프로젝트를 하나씩 내보내고 가져옵니다.

GitLab은 관리자 액세스 토큰을 사용하여 가져오기를 수행할 때 사용자 기여를 올바르게 매핑합니다. GitLab Self-Managed 인스턴스에서 GitLab.com으로 가져올 때 GitLab은 사용자 기여를 올바르게 매핑하지 않습니다. GitLab Self-Managed 인스턴스에서 GitLab.com으로 가져올 때 사용자 기여의 올바른 매핑은 전문 서비스 팀의 유료 개입으로 보존될 수 있습니다.

### 추가 정보 {#additional-information}

- 내보내기는 임시 디렉터리에 저장되고 특정 워커에 의해 24시간마다 삭제됩니다.
- 가져온 프로젝트의 그룹 수준 관계를 보존하려면 먼저 그룹을 내보내고 가져온 다음 프로젝트를 원하는 그룹 구조로 가져올 수 있습니다.
- 가져온 그룹에는 부모 그룹으로 가져오지 않는 한 `private` 가시성 수준이 지정됩니다.
- 부모 그룹으로 가져온 경우 서브그룹은 달리 제한되지 않는 한 동일한 수준의 가시성을 상속합니다.
- [Community Edition에서 Enterprise Edition으로](https://about.gitlab.com/install/) 그룹을 내보낼 수 있으며 그 반대도 가능합니다. Enterprise Edition은 Community Edition의 일부가 아닌 일부 그룹 데이터를 유지합니다. Enterprise Edition에서 Community Edition으로 그룹을 내보내는 경우 이 데이터가 손실될 수 있습니다. 자세한 내용은 [EE에서 CE로 되돌리기](../../../update/convert_to_ee/revert.md)를 참조하세요.

최대 가져오기 파일 크기는 GitLab Self-Managed 또는 GitLab.com으로 가져오는지에 따라 달라집니다:

- GitLab Self-Managed 인스턴스로 가져오는 경우 모든 크기의 가져오기 파일을 가져올 수 있습니다. 관리자는 다음 중 하나를 사용하여 이 동작을 변경할 수 있습니다:
  - [애플리케이션 설정 API](../../../api/settings.md#update-application-settings)에서 `max_import_size` 옵션을 사용하여.
  - [**운영자** 영역](../../../administration/settings/account_and_limit_settings.md).
- GitLab.com에서 최대 [5GB](../../gitlab_com/_index.md#account-and-limit-settings) 크기의 가져오기 파일을 사용하여 그룹을 가져올 수 있습니다.

### 호환성 {#compatibility-1}

그룹 파일 내보내기는 NDJSON 형식입니다.

GitLab 최대 2개 [마이너](../../../policy/maintenance.md#versioning) 버전 이전 버전에서 내보낸 그룹 파일 내보내기를 가져올 수 있습니다.

예를 들어:

| 대상 버전 | 호환 가능한 원본 버전 |
|:--------------------|:---------------------------|
| 13.0                | 13.0, 12.10, 12.9          |
| 13.1                | 13.1, 13.0, 12.10          |

### 내보낸 그룹 항목 {#group-items-that-are-exported}

[`import_export.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/import_export/group/import_export.yml) 파일은 파일 내보내기를 사용하여 그룹을 마이그레이션할 때 내보내고 가져온 항목을 나열합니다. 대상 GitLab 인스턴스로 가져올 수 있는 항목을 확인하려면 GitLab 버전의 분기에서 이 파일을 봅니다. 예를 들어 [`19-2-stable-ee` 분기의 `import_export.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/19-2-stable-ee/lib/gitlab/import_export/group/import_export.yml).

내보낸 그룹 항목에는 다음이 포함됩니다:

- 마일스톤
- 관련 레이블 우선순위가 없는 그룹 레이블
- 보드 및 보드 목록
- 배지
- 서브그룹(위의 모든 데이터 포함)
- 에픽
  - 에픽 리소스 상태 이벤트.
- 이벤트
- [위키](../wiki/group.md)
- 반복 주기.

### 내보내지지 않은 그룹 항목 {#group-items-that-are-not-exported}

내보내지지 않은 항목에는 다음이 포함됩니다:

- 프로젝트
- 러너 토큰
- SAML 검색 토큰
- 업로드

### 준비 {#preparation}

- 가져온 그룹의 구성원 목록 및 해당 권한을 보존하려면 이러한 그룹의 사용자를 검토합니다. 원하는 그룹을 가져오기 전에 이러한 사용자가 존재하는지 확인합니다.
- 사용자는 원본 GitLab 인스턴스에서 공개 이메일을 설정해야 하며, 이는 대상 GitLab 인스턴스에서 확인된 기본 이메일과 일치합니다. 대부분의 사용자는 이메일 주소를 확인하도록 요청하는 이메일을 받습니다.

### 그룹 내보내기 {#export-a-group}

사전 요구 사항:

- 그룹에 대한 소유자 역할이 있어야 합니다.

그룹의 내용을 내보내려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급** 섹션에서 **그룹 내보내기**를 선택합니다.
1. 내보내기가 생성된 후 다음을 수행할 수 있습니다:
   - 받아야 하는 이메일에 포함된 링크를 따릅니다.
   - 그룹 설정 페이지를 새로 고친 다음 **프로젝트 내보내기** 영역에서 **내보내기 다운로드**를 선택합니다.

### 그룹 가져오기 {#import-the-group}

그룹을 가져오려면:

1. 우측 상단 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 그룹**을 선택합니다.
1. **그룹 가져오기**를 선택합니다.
1. **파일에서 그룹 가져오기** 섹션에서 그룹 이름을 입력하고 관련 그룹 URL을 수락하거나 수정합니다.
1. **파일 선택**을 선택합니다.
1. 가져올 GitLab 내보내기 파일을 선택합니다.
1. 가져오기를 시작하려면 **가져오기**를 선택합니다.

### 속도 제한 {#rate-limits-1}

남용을 방지하기 위해 기본적으로 사용자는 다음으로 속도 제한됩니다:

| 요청 유형    | 한도 |
|-----------------|-------|
| 내보내기          | 분당 6개 그룹 |
| 내보내기 다운로드 | 그룹당 분당 1회 다운로드 |
| 가져오기          | 분당 6개 그룹 |

## 관련 항목 {#related-topics}

- [프로젝트 가져오기 및 내보내기 API](../../../api/project_import_export.md)
- [프로젝트 가져오기 및 내보내기 관리 Rake 작업](../../../administration/raketasks/project_import_export.md)
- [GitLab 그룹 마이그레이션](../../group/import/_index.md)
- [그룹 가져오기 및 내보내기 API](../../../api/group_import_export.md)
- [그룹을 직접 전송으로 마이그레이션](../../group/import/_index.md)
