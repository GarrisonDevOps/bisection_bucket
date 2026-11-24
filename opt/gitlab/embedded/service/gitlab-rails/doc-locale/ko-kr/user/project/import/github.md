---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitHub에서 마이그레이션
description: "GitHub에서 GitLab으로 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- **가져옴** 배지를 GitLab 17.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/461208)했습니다.
- **대체 댓글 가져오기 방법 사용** 체크박스를 GitLab 19.4에서 [제거](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250959)했습니다. 이 댓글 가져오기 방법은 이제 새 가져오기에 항상 사용되며 끌 수 없습니다.

{{< /history >}}

GitHub.com 또는 GitHub Enterprise에서 GitHub 프로젝트를 가져올 수 있습니다. 프로젝트를 가져오는 것은 GitHub에서 GitLab으로 그룹이나 조직의 모든 유형을 마이그레이션하거나 가져오지 않습니다.

가져온 이슈, 머지 리퀘스트, 댓글 및 이벤트는 GitLab에서 **가져옴** 배지를 가집니다.

네임스페이스는 `gitlab.com/sidney-jones` 또는 `gitlab.com/customer-success`과 같은 GitLab의 사용자 또는 그룹입니다.

GitLab UI를 사용하면 GitHub 임포터가 항상 `github.com` 도메인에서 가져옵니다. 자체 호스팅되는 GitHub Enterprise Server 도메인에서 가져오는 경우 GitLab 액세스 토큰(scope `api`)과 함께 [import API](#use-the-api) GitHub 엔드포인트를 사용합니다.

가져오기 전에 대상 네임스페이스와 대상 리포지토리 이름을 변경할 수 있습니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 가져오기 프로세스에 대한 개요는 [GitHub에서 GitLab으로 마이그레이션하는 방법(작업 포함)](https://www.youtube.com/watch?v=0Id5oMl1Kqs)을 참조하세요.

## 가져오기 기간 예상 {#estimating-import-duration}

GitHub에서의 모든 가져오기는 다르므로 수행하는 가져오기의 지속 시간에 영향을 미칩니다. 그러나 테스트에서 GitLab은 `https://github.com/kubernetes/kubernetes`을(를) 76시간에 가져왔습니다. 테스트에 따르면 프로젝트는 다음으로 구성되었습니다:

- 80,000개의 풀 리퀘스트입니다.
- 45,000개의 이슈입니다.
- 약 150만 개의 댓글입니다.

## 사전 요구 사항 {#prerequisites}

GitHub에서 프로젝트를 가져오려면 [GitHub 임포트 소스](../../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources)를 활성화해야 합니다. 해당 가져오기 소스가 활성화되지 않은 경우 GitLab 관리자에게 활성화하도록 요청합니다. GitHub 임포트 소스는 GitLab.com에서 기본적으로 활성화됩니다.

### 권한 및 역할 {#permissions-and-roles}

GitHub 임포터를 사용하려면 다음이 필요합니다:

- 소스 GitHub 프로젝트에 대한 액세스
- 대상 GitLab 그룹에 대한 유지보수자 또는 소유자 역할

또한 GitHub 리포지토리가 속한 조직은 가져오는 GitLab 인스턴스에 [써드파티 애플리케이션 액세스 정책](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions)의 제한을 부과하면 안 됩니다.

## 알려진 이슈 {#known-issues}

- 2017년 이전에 생성된 GitHub 풀 리퀘스트 댓글(GitLab에서는 diff 노트라고 함)을 별도의 스레드로 가져옵니다. 이는 2017년 이전의 댓글에 대해 `in_reply_to_id`을(를) 포함하지 않는 GitHub API의 제한으로 인해 발생합니다.
- [GitLab 18.3 이하](https://gitlab.com/gitlab-org/gitlab/-/issues/424400)에서 GitHub Enterprise Server 인스턴스의 리포지토리에서 Markdown 첨부 파일을 가져오지 않습니다. [GitLab 18.4 이상](https://gitlab.com/gitlab-org/gitlab/-/issues/553386):
  - Markdown 첨부 파일의 동영상 및 이미지 파일만 가져옵니다.
  - 다른 파일 첨부 파일은 가져오지 않습니다.
- [알려진 문제](https://gitlab.com/gitlab-org/gitlab/-/issues/418800) 때문에 [GitHub 자동 병합](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/automatically-merging-a-pull-request)을 사용한 프로젝트를 가져올 때 GitLab의 가져온 프로젝트는 커밋이 GitHub 내부 GPG 키로 서명된 경우 `unverified`으로 표시된 병합 커밋을 가질 수 있습니다.
- GitLab은 2023-05-09 이전에 프라이빗 리포지토리에 업로드된 GitHub Markdown 이미지 첨부 파일을 [가져올 수 없습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/424046). 이 문제가 발생하고 샘플 리포지토리를 제공할 의향이 있으면 [이슈 424046](https://gitlab.com/gitlab-org/gitlab/-/issues/424046)에 댓글을 추가하면 GitLab에서 연락하겠습니다.
- [GitLab 특정 참조](../../markdown.md#gitlab-specific-references)의 경우 GitLab은 이슈에 `#` 문자를 사용하고 머지 리퀘스트에 `!` 문자를 사용합니다. 그러나 GitHub은 이슈와 풀 리퀘스트 모두에 `#` 문자만 사용합니다. 가져올 때:

  - 댓글 노트, GitLab은 GitLab이 참조가 이슈를 가리키는지 또는 머지 리퀘스트를 가리키는지 판단할 수 없기 때문에 이슈에만 링크를 만듭니다.
  - 이슈 또는 머지 리퀘스트 설명, GitLab은 가져온 대응 항목이 아직 대상에 생성되지 않았을 수 있으므로 참조에 대한 링크를 만들지 않습니다.

- SAML 싱글 사인온(SSO)이 활성화된 GitHub 계정에서 가져올 때 Markdown 첨부 파일을 가져오지 못할 수 있습니다. 이 문제는 SSO가 강제될 때 개인 액세스 토큰을 사용하여 자산을 다운로드할 수 없는 GitHub API 제한으로 인해 발생합니다. 이 문제를 해결하려면 가져오기를 수행하는 GitLab 사용자를 GitHub 리포지토리에 [외부 협력자](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators/adding-outside-collaborators-to-repositories-in-your-organization)로 추가합니다. 이를 통해 가져오기 중에 프라이빗 첨부 파일에 액세스할 수 있습니다.

## GitHub 리포지토리를 GitLab으로 가져오기 {#import-your-github-repository-into-gitlab}

GitHub 리포지토리를 다음 중 하나로 가져올 수 있습니다:

- [GitHub OAuth 사용](#use-github-oauth)
- [GitHub 개인 액세스 토큰 사용](#use-a-github-personal-access-token)
- [API 사용](#use-the-api)

`github.com`에서 가져오는 경우 모든 방법을 사용하여 가져올 수 있습니다. 자체 호스팅되는 GitHub Enterprise Server 고객은 API를 사용해야 합니다.

### GitHub OAuth 사용 {#use-github-oauth}

GitLab.com으로 가져오거나 GitHub OAuth가 [구성](../../../integration/github.md)된 GitLab Self-Managed로 가져오는 경우 GitHub OAuth를 사용하여 리포지토리를 가져올 수 있습니다.

이 방법은 백엔드가 적절한 권한으로 액세스 토큰을 교환하기 때문에 [개인 액세스 토큰(PAT)](#use-a-github-personal-access-token) 사용보다 장점이 있습니다.

1. 오른쪽 상단 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 그리고 **새 프로젝트/리포지토리**를 선택합니다.
1. **프로젝트 가져오기**를 선택한 후 **GitHub**를 선택합니다.
1. **GitHub으로 인증**를 선택합니다.
1. [가져올 리포지토리 선택](#select-which-repositories-to-import)으로 진행합니다.

이전에 이 단계들을 수행한 후 다른 방법을 사용하여 가져오기를 수행하려면 GitLab 계정에서 로그아웃했다가 다시 로그인합니다.

### GitHub 개인 액세스 토큰 사용 {#use-a-github-personal-access-token}

GitHub 개인 액세스 토큰을 사용하여 GitHub 리포지토리를 가져오려면:

1. GitHub 개인 액세스 토큰을 생성합니다. 클래식 개인 액세스 토큰만 지원됩니다.
   1. <https://github.com/settings/tokens/new>로 이동합니다.
   1. **노트** 필드에 토큰 설명을 입력합니다.
   1. `repo` scope를 선택합니다.
   1. 선택 사항. [공동작업자 가져오기](#select-additional-items-to-import) 또는 프로젝트에 [Git LFS 파일](../../../topics/git/lfs/_index.md)이 있는 경우 `read:org` scope를 선택합니다.
   1. **토큰 생성**을 선택합니다.
1. 오른쪽 상단 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 그리고 **새 프로젝트/리포지토리**를 선택합니다.
1. **프로젝트 가져오기**를 선택한 후 **GitHub**를 선택합니다.
1. **GitHub으로 인증**를 선택합니다.
1. **개인 액세스 토큰** 필드에 GitHub 개인 액세스 토큰을 붙여넣습니다.
1. **인증**을 선택합니다.
1. [가져올 리포지토리 선택](#select-which-repositories-to-import)으로 진행합니다.

이전에 이 단계들을 수행한 후 다른 토큰을 사용하여 가져오기를 수행하려면 GitLab 계정에서 로그아웃했다가 다시 로그인하거나 GitHub에서 이전 토큰을 취소합니다.

### API 사용 {#use-the-api}

[import API](../../../api/import.md#import-repository-from-github)를 사용하여 GitHub 리포지토리를 가져올 수 있습니다. GitLab UI를 사용하는 것보다 몇 가지 장점이 있습니다:

- 공개 인 경우 소유하지 않은 GitHub 리포지토리를 가져오는 데 사용할 수 있습니다.
- 자체 호스팅되는 GitHub Enterprise Server에서 가져오는 데 사용할 수 있습니다.
- UI에서 사용할 수 없는 `timeout_strategy` 옵션을 설정하는 데 사용할 수 있습니다.

REST API는 GitLab 개인 액세스 토큰으로 인증하도록 제한됩니다.

GitLab REST API를 사용하여 GitHub 리포지토리를 가져오려면:

1. GitHub 개인 액세스 토큰을 생성합니다. 클래식 개인 액세스 토큰만 지원됩니다.
   1. <https://github.com/settings/tokens/new>로 이동합니다.
   1. **노트** 필드에 토큰 설명을 입력합니다.
   1. `repo` scope를 선택합니다.
   1. 선택 사항. [공동작업자 가져오기](#select-additional-items-to-import) 또는 프로젝트에 [Git LFS 파일](../../../topics/git/lfs/_index.md)이 있는 경우 `read:org` scope를 선택합니다.
   1. **토큰 생성**을 선택합니다.
1. [import API](../../../api/import.md#import-repository-from-github)를 사용하여 GitHub 리포지토리를 가져옵니다.

### 리포지토리 목록 필터링 {#filter-repositories-list}

GitHub 리포지토리에 대한 액세스를 승인하면 GitLab이 임포터 페이지로 리디렉션하고 GitHub 리포지토리가 나열됩니다.

다음 탭 중 하나를 사용하여 리포지토리 목록을 필터링합니다:

- **소유자**(기본값): 소유자인 리포지토리로 목록을 필터링합니다.
- **협업**: 기여한 리포지토리로 목록을 필터링합니다.
- **조직**: 회원인 조직에 속한 리포지토리로 목록을 필터링합니다.

**조직** 탭이 선택되면 드롭다운 목록에서 사용 가능한 GitHub 조직을 선택하여 검색을 더 좁힐 수 있습니다.

### 가져올 추가 항목 선택 {#select-additional-items-to-import}

가져오기를 최대한 빠르게 하기 위해 다음 항목은 기본적으로 GitHub에서 가져오지 않습니다:

- 리포지토리 댓글, 릴리스 게시물, 이슈 설명 및 풀 리퀘스트 설명의 Markdown 첨부 파일입니다. 여기에는 이미지, 텍스트 또는 바이너리 첨부 파일이 포함될 수 있습니다. 가져오지 않으면 Markdown의 첨부 파일에 대한 링크는 GitHub에서 첨부 파일을 제거한 후 끊어집니다.

이 항목들을 가져오도록 선택할 수 있지만 가져오기 시간이 크게 늘어날 수 있습니다. 이 항목들을 가져오려면 UI에서 적절한 필드를 선택합니다:

- **Markdown 첨부 파일 가져오기**.
- **공동작업자 가져오기**(기본적으로 선택됨). 선택된 상태로 두면 새 사용자가 그룹 또는 네임스페이스의 사용자를 사용하고 [프로젝트 소유자와 같은 높은](#collaborators-members) 권한이 부여될 수 있습니다. 직접 협력자만 가져옵니다. 외부 협력자는 절대 가져오지 않습니다. [GitLab 18.4 이상](https://gitlab.com/gitlab-org/gitlab/-/issues/559224)에서 공동작업자를 가져올 때 [**이 그룹의 프로젝트에 사용자를 추가할 수 없습니다.** 설정](../../group/access_and_permissions.md#prevent-members-from-being-added-to-projects-in-a-group)을 존중합니다.

### 가져올 리포지토리 선택 {#select-which-repositories-to-import}

기본적으로 제안된 리포지토리 네임스페이스는 GitHub에 존재하는 이름과 일치하지만 권한에 따라 가져오기를 진행하기 전에 이 이름을 편집하도록 선택할 수 있습니다.

가져올 리포지토리를 선택하려면 여러 리포지토리 옆에서 **가져오기**를 선택하거나 **모든 리포지토리 가져오기**를 선택합니다.

또한 이름으로 프로젝트를 필터링할 수 있습니다. 필터가 적용되면 **모든 리포지토리 가져오기**는 일치하는 리포지토리만 가져옵니다.

**상태** 열은 각 리포지토리의 가져오기 상태를 표시합니다. 페이지를 열어두고 실시간으로 업데이트를 확인하거나 나중에 돌아올 수 있습니다.

보류 중이거나 진행 중인 가져오기를 취소하려면 가져온 프로젝트 옆에서 **취소**를 선택합니다. 가져오기가 이미 시작된 경우 가져온 파일이 유지됩니다.

리포지토리를 가져온 후 GitLab URL에서 열려면 GitLab 경로를 선택합니다.

완료된 가져오기는 **다시 가져오기**를 선택하고 새 이름을 지정하여 다시 가져올 수 있습니다. 이렇게 하면 소스 프로젝트의 새 복사본이 생성됩니다.

![GitLab으로 가져올 리포지토리를 나열하는 GitHub 임포터 페이지입니다.](img/import_projects_from_github_importer_v16_0.png)

### 가져오기 상태 확인 {#check-status-of-imports}

가져오기가 완료되면 세 가지 상태 중 하나가 될 수 있습니다:

- **완료**: GitLab이 모든 리포지토리 엔티티를 가져왔습니다.
- **부분적으로 완료됨**: GitLab이 일부 리포지토리 엔티티를 가져오지 못했습니다.
- **실패함**: GitLab이 중대한 오류가 발생한 후 가져오기를 중단했습니다.

**상세정보**를 확장하여 가져오지 못한 [리포지토리 엔티티](#imported-data) 목록을 확인합니다.

## 사용자명 언급 {#username-mentions}

{{< history >}}

- GitLab 17.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/477553)했습니다.

{{< /history >}}

GitLab은 이슈, 머지 리퀘스트 및 노트의 사용자명 언급에 백틱을 추가합니다. 이러한 백틱은 GitLab 인스턴스에서 동일한 사용자명으로 잘못된 사용자에게 링크하는 것을 방지합니다.

## 사용자 기여 및 멤버십 매핑 {#user-contribution-and-membership-mapping}

{{< history >}}

- GitLab 17.8에서 GitLab.com에서 [변경](https://gitlab.com/groups/gitlab-org/-/work_items/14667)되어 [**사용자 기여 및 멤버십 매핑**](../../import/mapping/post_migration_mapping.md)으로 변경했습니다.
- GitLab 17.8에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/176675)했습니다.

{{< /history >}}

GitHub 임포터는 GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에 대해 사용자 기여를 매핑하는 [사후 마이그레이션 방법](../../import/mapping/post_migration_mapping.md)을 사용합니다.

### 매핑의 대체 방법 {#alternative-method-of-mapping}

GitLab 18.7 이하에서 `github_user_mapping` 기능 플래그를 비활성화하여 가져오기에 대한 대체 사용자 기여 매핑 방법을 사용할 수 있습니다.

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 이 기능은 권장되지 않으며 다음의 경우 사용할 수 없습니다:
>
> - GitLab.com으로의 마이그레이션.
> - GitLab Self-Managed 및 GitLab Dedicated 18.8 이상으로의 마이그레이션입니다.
>
> 이 매핑 방법에서 발견된 문제는 수정될 가능성이 낮습니다. 이러한 제한 사항이 없는 [마이그레이션 후 방법](../../import/mapping/post_migration_mapping.md)을 대신 사용합니다.
>
> 자세한 내용은 [이슈 510963](https://gitlab.com/gitlab-org/gitlab/-/work_items/510963)을 참조합니다.

요구 사항:

- 리포지토리의 각 GitHub 작성자 및 할당자는 [공개 이메일 주소](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-email-preferences/setting-your-commit-email-address)를 가져야 합니다. GitHub Enterprise는 공개 이메일 주소를 요구하지 않으므로 기존 계정에 추가해야 할 수도 있습니다.
- GitHub 사용자의 이메일 주소는 GitLab 이메일 주소와 일치해야 합니다.
- GitHub의 사용자 이메일 주소가 GitLab에서 보조 이메일 주소로 설정된 경우 확인해야 합니다.

이 방법을 사용하면 사용자가 가져오기 중에 매핑됩니다.

요구 사항이 충족되지 않으면 임포터가 특정 사용자의 기여를 매핑할 수 없습니다. 이 경우:

- 프로젝트 생성자는 이슈 및 머지 리퀘스트의 작성자 및 할당자로 설정됩니다. 프로젝트 생성자는 일반적으로 가져오기 프로세스를 시작한 사용자입니다. 풀 리퀘스트, 이슈, 노트와 같은 설명 또는 노트가 있는 일부 기여의 경우 임포터가 원래 기여를 생성한 사람의 세부 정보로 텍스트를 수정합니다.
- GitHub의 풀 리퀘스트에 추가된 검토자 및 승인을 가져올 수 없습니다. 이 경우 임포터는 존재하지 않는 사용자가 검토자 및 승인자로 추가되었음을 설명하는 댓글을 생성합니다. 그러나 실제 검토자 상태 및 승인은 GitLab의 머지 리퀘스트에 적용되지 않습니다.

## 리포지토리 미러링 및 파이프라인 상태 공유 {#mirror-a-repository-and-share-pipeline-status}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

GitLab 티어에 따라 [리포지토리 미러링](../repository/mirror/_index.md)을 설정하여 가져온 리포지토리를 GitHub 복사본과 동기화된 상태로 유지할 수 있습니다.

또한 [GitHub Project Integration](../integrations/github.md)을 사용하여 파이프라인 상태 업데이트를 GitHub로 다시 전송하도록 GitLab을 구성할 수 있습니다.

[외부 리포지토리용 CI/CD](../../../ci/ci_cd_for_external_repos/_index.md)를 사용하여 프로젝트를 가져오는 경우 두 기능이 자동으로 구성됩니다.

> [!note]
> 미러링은 GitHub 프로젝트에서 새로운 또는 업데이트된 풀 리퀘스트를 동기화하지 않습니다.

## GitLab Self-Managed 인스턴스에서 가져오기 속도 개선 {#improve-the-speed-of-imports-on-gitlab-self-managed-instances}

GitLab 서버의 관리자 액세스가 이러한 단계에 필요합니다.

### Sidekiq 워커 수 증가 {#increase-the-number-of-sidekiq-workers}

대규모 프로젝트의 경우 모든 데이터를 가져오는 데 시간이 걸릴 수 있습니다. 필요한 시간을 줄이려면 다음 대기열을 처리하는 Sidekiq 워커 수를 증가할 수 있습니다:

- `github_importer`
- `github_importer_advance_stage`

최적의 환경을 위해 이러한 대기열만 처리하는 최소 4개의 Sidekiq 프로세스(각각 CPU 코어 수와 같은 스레드 수 실행)를 권장합니다. 이러한 프로세스가 별도의 서버에서 실행되도록 권장합니다. 8개 코어가 있는 4개 서버의 경우 최대 32개 개체(예: 이슈)를 병렬로 가져올 수 있습니다.

리포지토리 복제에 소요되는 시간을 줄이려면 네트워크 처리량, CPU 용량 및 디스크 성능(예: 고성능 SSD 사용)을 증가할 수 있습니다. 이는 Git 리포지토리를 저장하는 디스크(GitLab 인스턴스용)에 해당합니다. Sidekiq 워커 수를 증가하면 리포지토리 복제에 소요되는 시간이 줄어들지 않습니다.

### GitHub Enterprise Cloud OAuth 앱을 사용하여 GitHub OAuth 활성화 {#enable-github-oauth-using-a-github-enterprise-cloud-oauth-app}

[GitHub Enterprise Cloud 조직](https://docs.github.com/en/enterprise-cloud@latest/get-started/onboarding)에 속하는 경우 GitLab Self-Managed를 구성하여 더 높은 [GitHub API 속도 제한](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#primary-rate-limit-for-authenticated-users)을 얻을 수 있습니다.

GitHub API 요청은 일반적으로 시간당 5,000개의 요청 속도 제한이 적용됩니다. 아래 단계를 사용하면 시간당 15,000개의 요청 속도 제한이 높아져 전체 가져오기 시간이 더 빨라집니다.

사전 요구 사항:

- [GitHub Enterprise Cloud 조직](https://docs.github.com/en/enterprise-cloud@latest/get-started/onboarding/getting-started-with-github-enterprise-cloud)에 액세스할 수 있습니다.
- GitLab은 [GitHub OAuth](../../../integration/github.md#enable-github-oauth-in-gitlab)를 활성화하도록 구성되어 있습니다.

더 높은 속도 제한을 활성화하려면:

- [GitHub에서 OAuth 앱 생성](../../../integration/github.md#create-an-oauth-app-in-github)합니다. OAuth 앱이 개인 GitHub 계정이 아닌 Enterprise Cloud Organization에서 소유되는지 확인합니다.
- [GitHub OAuth](#use-github-oauth)를 사용하여 프로젝트 가져오기를 수행합니다.
- 선택 사항. 기본적으로 구성된 모든 OAuth 공급자에 대해 로그인이 활성화됩니다. GitHub OAuth를 가져오기에 사용하되 사용자가 GitHub으로 GitLab 인스턴스에 로그인할 수 없도록 하려면 [GitHub으로 로그인 비활성화](../../../integration/omniauth.md#enable-or-disable-sign-in-with-an-omniauth-provider-without-disabling-import-sources)할 수 있습니다.

## 가져온 데이터 {#imported-data}

프로젝트의 다음 항목이 가져옵니다:

- 열린 풀 리퀘스트와 관련된 프로젝트의 모든 포크 브랜치

  > [!note]
  > 포크 브랜치는 `GH-SHA-username/pull-request-number/fork-name/branch`과 유사한 명명 스키마로 가져옵니다.

- 모든 프로젝트 브랜치
- 다음에 대한 첨부 파일:
  - 댓글
  - 이슈 설명
  - 풀 리퀘스트 설명
  - 릴리스 정보
- 브랜치 보호 규칙
- [협력자(멤버)](#collaborators-members)
- [Git LFS 개체](../../../topics/git/lfs/_index.md)
- Git 리포지토리 데이터
- 이슈 및 풀 리퀘스트 댓글
- 이슈 및 풀 리퀘스트 이벤트([추가 항목](#select-additional-items-to-import)으로 가져올 수 있음)
- 이슈
- 레이블
- 마일스톤
- 풀 리퀘스트 할당된 검토자
- 병합된 풀 리퀘스트 정보
- 풀 리퀘스트 검토
- 풀 리퀘스트 검토 댓글
- 토론에 대한 풀 리퀘스트 검토 회신
- 풀 리퀘스트 검토 제안
- 풀 리퀘스트
- 릴리스 정보 내용
- 리포지토리 설명
- 위키 페이지

풀 리퀘스트 및 이슈에 대한 참조가 유지됩니다. 각 가져온 리포지토리는 [표시 수준이 제한](../../public_access.md#restrict-use-of-public-or-internal-projects)되지 않는 한 표시 수준을 유지합니다. 이 경우 기본 프로젝트 표시 수준으로 기본값이 지정됩니다.

### 브랜치 보호 규칙 및 프로젝트 설정 {#branch-protection-rules-and-project-settings}

가져온 GitHub 브랜치 보호 규칙은 다음 중 하나로 매핑됩니다:

- GitLab 브랜치 보호 규칙
- 프로젝트 전체 GitLab 설정

| GitHub 규칙                                                                                         | GitLab 규칙                                                                                                                                                                                                                                                          |
|:----------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 프로젝트의 기본 브랜치에 대해 **병합 전에 대화 해결 필요**                 | **모든 스레드가 해결되어야 합니다.** [프로젝트 설정](../merge_requests/_index.md#prevent-merge-unless-all-threads-are-resolved)                                                                                                                                         |
| **병합 전에 풀 리퀘스트 필요**                                                           | **푸시와 머지가 허용됨**의 **아무도 없음** 옵션 [브랜치 보호 설정](../repository/branches/protected.md#protect-a-branch)                                                                                                            |
| 프로젝트의 기본 브랜치에 대해 **서명된 커밋 필요**                                         | **서명되지 않은 커밋 거부** GitLab [푸시 규칙](../repository/push_rules.md#require-signed-commits)                                                                                                                                                          |
| **강제 푸시 허용 - 모두**                                                                   | **강제 푸시 허용** [브랜치 보호 설정](../repository/branches/protected.md#allow-force-push)                                                                                                                                               |
| **병합 전에 풀 리퀘스트 필요 - 코드 소유자의 검토 필요**                         | **코드 소유자의 승인이 필요합니다.** [브랜치 보호 설정](../repository/branches/protected.md#require-code-owner-approval)                                                                                                                        |
| **병합 전에 풀 리퀘스트 필요 - 특정 행위자가 필수 풀 리퀘스트를 무시하도록 허용** | **푸시와 머지가 허용됨** [브랜치 보호 설정](../repository/branches/protected.md#protect-a-branch)의 사용자 목록입니다. GitLab Premium 구독 없이는 푸시와 머지가 허용되는 사용자 목록이 역할로 제한됩니다. |

**병합 전에 상태 확인 통과 필요** GitHub 규칙을 가져오지 않습니다. [외부 상태 확인](../merge_requests/status_checks.md)을 수동으로 생성할 수 있습니다. 자세한 내용은 [이슈 370948](https://gitlab.com/gitlab-org/gitlab/-/issues/370948)을 참조합니다.

### 협력자(멤버) {#collaborators-members}

이러한 GitHub 협력자 역할은 이러한 GitLab [멤버 역할](../../permissions.md#roles)로 매핑됩니다:

| GitHub 역할 | 매핑된 GitLab 역할 |
|:------------|:-------------------|
| 읽기        | Guest              |
| 심사      | Reporter           |
| 작성       | Developer          |
| 유지    | Maintainer         |
| 관리       | Owner              |

GitHub Enterprise Cloud는 [사용자 정의 리포지토리 역할](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/about-custom-repository-roles)을 가집니다. 이러한 역할은 지원되지 않으며 부분적으로 완료된 가져오기를 야기합니다.

GitHub 협력자를 가져오려면 GitHub 프로젝트에 Write 또는 Maintain 역할이 있어야 합니다. 그렇지 않으면 협력자 가져오기를 건너뜁니다.

## 내부 네트워크에서 GitHub Enterprise에서 가져오기 {#import-from-github-enterprise-on-an-internal-network}

GitHub Enterprise 인스턴스가 인터넷에 액세스할 수 없는 내부 네트워크에 있는 경우 역방향 프록시를 사용하여 GitLab.com이 인스턴스에 액세스할 수 있도록 할 수 있습니다.

프록시는 다음을 수행해야 합니다:

- GitHub Enterprise 인스턴스로 요청을 전달합니다.
- 다음에서 내부 호스트명의 모든 발생을 공개 프록시 호스트명으로 변환합니다:
  - API 응답 본문입니다.
  - API 응답 `Link` 헤더입니다.

GitHub API는 페이지 매김을 위해 `Link` 헤더를 사용합니다.

프록시를 구성한 후 API 요청을 만들어 테스트합니다. 다음은 API를 테스트하기 위한 몇 가지 예제 명령입니다:

```shell
curl --header "Authorization: Bearer <YOUR-TOKEN>" "https://{PROXY_HOSTNAME}/user"

### URLs in the response body should use the proxy hostname

{
  "login": "example_username",
  "id": 1,
  "url": "https://{PROXY_HOSTNAME}/users/example_username",
  "html_url": "https://{PROXY_HOSTNAME}/example_username",
  "followers_url": "https://{PROXY_HOSTNAME}/api/v3/users/example_username/followers",
  ...
  "created_at": "2014-02-11T17:03:25Z",
  "updated_at": "2022-10-18T14:36:27Z"
}
```

```shell
curl --head --header "Authorization: Bearer <YOUR-TOKEN>" "https://{PROXY_DOMAIN}/api/v3/repos/{repository_path}/pulls?states=all&sort=created&direction=asc"

### Link header should use the proxy hostname

HTTP/1.1 200 OK
Date: Tue, 18 Oct 2022 21:42:55 GMT
Server: GitHub.com
Content-Type: application/json; charset=utf-8
Cache-Control: private, max-age=60, s-maxage=60
...
X-OAuth-Scopes: repo
X-Accepted-OAuth-Scopes:
github-authentication-token-expiration: 2022-11-22 18:13:46 UTC
X-GitHub-Media-Type: github.v3; format=json
X-RateLimit-Limit: 5000
X-RateLimit-Remaining: 4997
X-RateLimit-Reset: 1666132381
X-RateLimit-Used: 3
X-RateLimit-Resource: core
Link: <https://{PROXY_DOMAIN}/api/v3/repositories/1/pulls?page=2>; rel="next", <https://{PROXY_DOMAIN}/api/v3/repositories/1/pulls?page=11>; rel="last"
```

또한 프록시를 사용하여 리포지토리를 복제하지 못하는지 확인합니다:

```shell
git clone -c http.extraHeader="Authorization: basic <base64 encode YOUR-TOKEN>" --mirror https://{PROXY_DOMAIN}/{REPOSITORY_PATH}.git
```

### 샘플 역방향 프록시 구성 {#sample-reverse-proxy-configuration}

다음 구성은 Apache HTTP Server를 역방향 프록시로 구성하는 방법의 예입니다.

> [!warning]
> 간단히 하기 위해 조각에는 클라이언트와 프록시 간의 연결을 암호화하는 구성이 없습니다. 그러나 보안상의 이유로 이 구성을 포함해야 합니다. [샘플 Apache TLS/SSL 구성](https://ssl-config.mozilla.org/#server=apache&version=2.4.41&config=intermediate&openssl=1.1.1k&guideline=5.6)을 참조하세요.

```plaintext
# Required modules
LoadModule filter_module lib/httpd/modules/mod_filter.so
LoadModule reflector_module lib/httpd/modules/mod_reflector.so
LoadModule substitute_module lib/httpd/modules/mod_substitute.so
LoadModule deflate_module lib/httpd/modules/mod_deflate.so
LoadModule headers_module lib/httpd/modules/mod_headers.so
LoadModule proxy_module lib/httpd/modules/mod_proxy.so
LoadModule proxy_connect_module lib/httpd/modules/mod_proxy_connect.so
LoadModule proxy_http_module lib/httpd/modules/mod_proxy_http.so
LoadModule ssl_module lib/httpd/modules/mod_ssl.so

<VirtualHost GITHUB_ENTERPRISE_HOSTNAME:80>
  ServerName GITHUB_ENTERPRISE_HOSTNAME

  # Enables reverse-proxy configuration with SSL support
  SSLProxyEngine On
  ProxyPass "/" "https://GITHUB_ENTERPRISE_HOSTNAME/"
  ProxyPassReverse "/" "https://GITHUB_ENTERPRISE_HOSTNAME/"

  # Replaces occurrences of the local GitHub Enterprise URL with the Proxy URL
  # GitHub Enterprise compresses the responses, the filters INFLATE and DEFLATE needs to be used to
  # decompress and compress the response back
  AddOutputFilterByType INFLATE;SUBSTITUTE;DEFLATE application/json
  Substitute "s|https://GITHUB_ENTERPRISE_HOSTNAME|https://PROXY_HOSTNAME|ni"
  SubstituteMaxLineLength 50M

  # GitHub API uses the response header "Link" for the API pagination
  # For example:
  #   <https://example.com/api/v3/repositories/1/issues?page=2>; rel="next", <https://example.com/api/v3/repositories/1/issues?page=3>; rel="last"
  # The directive below replaces all occurrences of the GitHub Enterprise URL with the Proxy URL if the
  # response header Link is present
  Header edit* Link "https://GITHUB_ENTERPRISE_HOSTNAME" "https://PROXY_HOSTNAME"
</VirtualHost>
```

## 관련 항목 {#related-topics}

- [가져오기 및 내보내기 설정](../../../administration/settings/import_and_export_settings.md).
- [가져오기를 위한 Sidekiq 구성](../../../administration/sidekiq/configuration_for_imports.md).
- [여러 Sidekiq 프로세스 실행](../../../administration/sidekiq/extra_sidekiq_processes.md).
- [특정 작업 클래스 처리](../../../administration/sidekiq/processing_specific_job_classes.md).
