---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Gitea에서 마이그레이션
description: "Gitea에서 GitLab으로 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 경로에 `.`이(가) 있는 프로젝트를 가져오는 기능이 GitLab 16.11에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/issues/434175)되었습니다.
- 일부 가져온 항목에 **가져옴** 배지가 GitLab 17.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/461208)되었습니다.
- [GitLab.com에서 변경되어](https://gitlab.com/groups/gitlab-org/-/work_items/14667) GitLab 17.8에서 [마이그레이션 후 사용자 기여 및 멤버십 매핑](mapping/post_migration_mapping.md)으로 변경되었습니다.
- 마이그레이션 후 사용자 및 기여 멤버십 매핑이 GitLab 17.8에서 [GitLab.com 및 GitLab Self-Managed에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/176675)되었습니다.

{{< /history >}}

Gitea에서 GitLab으로 프로젝트를 가져옵니다.

Gitea 임포터는 Gitea의 항목 부분집합을 가져옵니다.

| Gitea 항목                    | 가져옴 |
|:------------------------------|:---------|
| 리포지토리 설명        | {{< yes >}} |
| Git 리포지토리 데이터           | {{< yes >}} |
| 이슈                        | {{< yes >}} |
| 풀 리퀘스트                 | {{< yes >}} |
| 마일스톤                    | {{< yes >}} |
| 레이블                        | {{< yes >}} |
| 풀 리퀘스트의 diff 주석 |          |

## 임포터 워크플로우 {#importer-workflow}

Gitea 임포터는 GitLab.com 및 GitLab Self-Managed의 사용자 기여 마이그레이션 후 매핑을 지원합니다. 임포터는 매핑의 [대체 방법](#alternative-method-of-mapping)도 지원합니다.

가져올 때:

- 리포지토리 공개 액세스가 유지됩니다. Gitea에서 리포지토리가 비공개인 경우 GitLab에서도 비공개로 생성됩니다.
- 가져온 이슈, 머지 리퀘스트, 댓글은 GitLab에서 **가져옴** 배지를 포함합니다.
- Gitea가 OAuth 제공자가 아니기 때문에 작성자 또는 담당자를 GitLab 인스턴스의 사용자에게 매핑할 수 없습니다. 프로젝트 생성자(일반적으로 가져오기 프로세스를 시작한 사용자)가 작성자로 설정됩니다. 이슈의 경우 원본 Gitea 작성자를 계속 볼 수 있습니다.
- GitLab은 존재하지 않는 네임스페이스 또는 그룹을 자동으로 생성하지 않으며 네임스페이스 또는 그룹 이름이 중복된 경우 개인 네임스페이스로 폴백하지 않습니다.

## 사전 요구 사항 {#prerequisites}

- Gitea 버전 1.0.0 이상.
- [Gitea 가져오기 소스](../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources)를 활성화하거나 GitLab 관리자에게 활성화하도록 요청해야 합니다. GitLab.com에서 기본적으로 활성화됩니다.
- 가져올 대상 그룹에서 유지보수자 또는 소유자 역할.

## Gitea 리포지토리 가져오기 {#import-your-gitea-repositories}

가져오기 중에 개인 액세스 토큰을 생성하고 GitLab이 리포지토리에 액세스할 수 있도록 Gitea로 일회성 인증을 수행합니다.

Gitea 리포지토리를 가져오려면:

1. 오른쪽 상단 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 그리고 **새 프로젝트/리포지토리**를 선택합니다.
1. 가져오기 인증 프로세스를 시작하려면 **Gitea**를 선택합니다.
1. `https://your-gitea-instance/user/settings/applications`로 이동합니다. `your-gitea-instance`를 Gitea 인스턴스의 호스트로 바꿉니다.
1. **새 토큰 생성**을 선택합니다.
1. 토큰 설명을 입력합니다.
1. **토큰 생성**을 선택합니다.
1. 토큰 해시를 복사합니다.
1. GitLab으로 돌아가 Gitea 임포터에 토큰을 제공합니다.
1. **Gitea 리포지토리 리스트**를 선택하고 GitLab이 리포지토리 정보를 읽을 때까지 기다립니다. 완료되면 GitLab은 가져올 리포지토리를 선택하는 임포터 페이지를 표시합니다. 여기에서 Gitea 리포지토리의 가져오기 상태를 볼 수 있습니다:

   - 가져오기 중인 항목은 시작됨 상태를 표시합니다.
   - 이미 성공적으로 가져온 항목은 완료됨 상태로 녹색으로 표시됩니다.
   - 아직 가져오지 않은 항목의 테이블 오른쪽에 **가져오기**가 있습니다.
   - 이미 가져온 항목의 테이블 오른쪽에 **다시 가져오기**가 있습니다.

1. Gitea 리포지토리 가져오기를 완료하려면 다음을 할 수 있습니다:

   - 모든 Gitea 프로젝트를 한 번에 가져옵니다. 좌측 상단에서 **모든 프로젝트 가져오기**를 선택합니다.
   - 프로젝트 이름을 기준으로 필터링하여 선택된 프로젝트만 가져옵니다. 필터를 적용하면 **모든 프로젝트 가져오기**는 선택된 프로젝트만 가져옵니다.
   - 권한이 있는 경우 프로젝트의 다른 이름과 다른 네임스페이스를 선택합니다.

## 매핑의 대체 방법 {#alternative-method-of-mapping}

GitLab 18.5 이전에는 `gitea_user_mapping` 기능 플래그를 비활성화하여 가져오기의 대체 사용자 기여 매핑 방법을 사용할 수 있습니다.

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 이 기능은 권장되지 않으며 다음의 경우 사용할 수 없습니다:
>
> - GitLab.com으로의 마이그레이션.
> - GitLab Self-Managed 및 GitLab Dedicated 18.6 이상으로의 마이그레이션.
>
> 이 매핑 방법에서 발견된 문제는 수정될 가능성이 낮습니다. 이러한 제한 사항이 없는 [마이그레이션 후 방법](mapping/post_migration_mapping.md)을 대신 사용합니다.
>
> 자세한 내용은 [이슈 512211](https://gitlab.com/gitlab-org/gitlab/-/work_items/512211)을 참조하세요.

이 방법을 사용하면 사용자 기여가 기본적으로 프로젝트 생성자(일반적으로 가져오기 프로세스를 시작한 사용자)에게 할당됩니다.

## 관련 항목 {#related-topics}

- [가져오기 및 내보내기 설정](../../administration/settings/import_and_export_settings.md).
- [가져오기를 위한 Sidekiq 구성](../../administration/sidekiq/configuration_for_imports.md).
- [여러 Sidekiq 프로세스 실행](../../administration/sidekiq/extra_sidekiq_processes.md).
- [특정 작업 클래스 처리](../../administration/sidekiq/processing_specific_job_classes.md).
