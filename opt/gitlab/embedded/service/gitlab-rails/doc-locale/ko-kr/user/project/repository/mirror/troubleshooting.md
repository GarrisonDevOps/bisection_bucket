---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab 프로젝트의 리포지토리 미러링 문제 해결.
title: 리포지토리 미러링 문제 해결
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

미러링이 실패하면 GitLab에서 프로젝트 세부 정보 페이지에 경고를 표시합니다. 예: {{< icon name="warning-solid" >}} **1시간 전에 풀 미러링 실패** 경고 텍스트를 선택하여 **리포지토리 미러링** 설정으로 이동합니다.

영향을 받는 리포지토리 옆에 GitLab은 **오류** 배지를 표시합니다. 오류 메시지를 보려면 배지 위에 마우스를 가져갑니다. 오류 메시지에는 인증 실패나 분기된 브랜치와 같은 일반적인 문제에 대한 구체적인 세부 정보가 포함됩니다. 다른 오류는 Git 작업에서 직접 발생할 수 있습니다.

## GitHub에서 오류 코드 2로 RST_STREAM 수신 {#received-rst_stream-with-error-code-2-with-github}

GitHub 리포지토리로 미러링할 때 이 메시지가 나타나면:

```plaintext
13:Received RST_STREAM with error code 2
```

다음 문제 중 하나가 발생할 수 있습니다:

1. GitHub 설정이 커밋에 사용된 이메일 주소를 노출하는 푸시를 차단하도록 설정되어 있을 수 있습니다. 이 문제를 해결하려면 다음 중 하나를 수행하세요:
   - GitHub 이메일 주소를 공개로 설정합니다.
   - [**내 이메일을 노출하는 명령줄 푸시 차단**](https://github.com/settings/emails) 설정을 끕니다.
1. 리포지토리가 GitHub 파일 크기 제한인 100MB를 초과합니다. 이 문제를 해결하려면 GitHub에 구성된 파일 크기 제한을 확인하고 [Git Large File Storage(LFS)](https://git-lfs.com/)를 사용하여 대용량 파일을 관리하는 것을 고려하세요.

## 기한 초과 {#deadline-exceeded}

GitLab을 업그레이드하면 사용자 이름 표현 방식이 변경되어 `%40` 문자를 `@`로 바꾸기 위해 미러링 사용자 이름과 비밀번호를 업데이트해야 합니다.

## 연결 차단: 서버가 공개 키 인증만 허용 {#connection-blocked-server-only-allows-public-key-authentication}

GitLab과 원격 리포지토리 간의 연결이 차단됩니다. [TCP 확인](../../../../administration/raketasks/maintenance.md#check-tcp-connectivity-to-a-remote-site)이 성공하더라도 GitLab에서 원격 서버로의 경로에 있는 모든 네트워킹 구성 요소에서 차단을 확인해야 합니다.

이 오류는 방화벽이 나가는 패킷에 대해 `Deep SSH Inspection`를 수행할 때 발생할 수 있습니다.

## 사용자 이름을 읽을 수 없음: 터미널 프롬프트 비활성화 {#could-not-read-username-terminal-prompts-disabled}

[외부 리포지토리를 위한 GitLab CI/CD](../../../../ci/ci_cd_for_external_repos/_index.md)를 사용하여 새 프로젝트를 생성한 후 이 오류가 나타나면:

- Bitbucket Cloud에서:

  ```plaintext
  "2:fetch remote: "fatal: could not read Username for 'https://bitbucket.org':
  terminal prompts disabled\n": exit status 128."
  ```

- Bitbucket Server(자체 호스팅)에서:

  ```plaintext
  "2:fetch remote: "fatal: could not read Username for 'https://lab.example.com':
  terminal prompts disabled\n": exit status 128.
  ```

미러링된 리포지토리의 URL에 리포지토리 소유자가 지정되어 있는지 확인합니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **리포지토리 미러링**을 펼칩니다.
1. 리포지토리 소유자가 지정되어 있지 않으면 이 형식으로 URL을 다시 삭제하고 추가하여 `OWNER`, `ACCOUNTNAME`, `PATH_TO_REPO`, `REPONAME`를 사용자의 값으로 바꿉니다:

   - Bitbucket Cloud에서:

     ```plaintext
     https://OWNER@bitbucket.org/ACCOUNTNAME/REPONAME.git
     ```

   - Bitbucket Server(자체 호스팅)에서:

     ```plaintext
     https://OWNER@lab.example.com/PATH_TO_REPO/REPONAME.git
     ```

미러링을 위해 Cloud 또는 자체 호스팅 Bitbucket 리포지토리에 연결할 때 리포지토리 소유자가 문자열에 필요합니다.

## 푸시 미러: `LFS objects are missing` {#push-mirror-lfs-objects-are-missing}

다음과 같은 오류가 표시될 수 있습니다:

```plaintext
GitLab: GitLab: LFS objects are missing. Ensure LFS is properly set up or try a manual "git lfs push --all".
```

이 문제는 푸시 미러링에 SSH 리포지토리 URL을 사용할 때 발생합니다. SSH를 통해 LFS 파일을 전송하는 푸시 미러링은 지원되지 않습니다.

해결 방법은 푸시 미러에 대해 SSH 대신 HTTPS 리포지토리 URL을 사용하는 것입니다.

[문제 249587](https://gitlab.com/gitlab-org/gitlab/-/issues/249587)이 이 문제를 해결하기 위해 존재합니다.

## 오류: `Committer is not a member of team` {#error-committer-is-not-a-member-of-team}

다음과 같은 오류가 표시될 수 있습니다:

```plaintext
remote: GitLab: Committer 'noreply@example.com' is not a member of team
```

이 문제는 소스 프로젝트가 GitLab UI에서 만든 커밋에 서명하고 대상 프로젝트가 **커밋 작성자가 GitLab 사용자인지 확인** [푸시 규칙](../push_rules.md#verify-users)이 켜져 있을 때 발생합니다. GitLab에서 서명한 커밋은 인스턴스 이메일 주소를 커밋자로 사용하며, 이 주소는 GitLab 사용자에게 속하지 않습니다.

GitLab 19.3 이상에서는 이 문제를 해결합니다: 푸시 규칙이 더 이상 [GitLab에서 서명한 커밋](../push_rules.md#commits-signed-by-gitlab)의 커밋자 이메일 주소를 확인하지 않습니다. 이전 버전의 해결 방법으로, 대상 프로젝트에서 푸시 규칙을 끕니다.

## 풀 미러에서 LFS 파일 누락 {#pull-mirror-is-missing-lfs-files}

경우에 따라 풀 미러링이 LFS 파일을 전송하지 않습니다. 이 문제는 SSH 리포지토리 URL을 사용할 때 발생합니다.

해결 방법은 대신 HTTPS 리포지토리 URL을 사용하는 것입니다.

## 풀 미러링이 파이프라인을 트리거하지 않음 {#pull-mirroring-is-not-triggering-pipelines}

여러 이유로 파이프라인이 실행되지 않을 수 있습니다:

- [미러 업데이트를 위한 파이프라인 트리거](pull.md#trigger-pipelines-for-mirror-updates)가 활성화되지 않을 수 있습니다. 이 설정은 초기에 [풀 미러링을 구성](pull.md#configure-pull-mirroring)할 때만 활성화할 수 있습니다. 상태가 나중에 프로젝트를 확인할 때 [표시되지 않습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/346630).

  [외부 리포지토리를 위한 CI/CD](../../../../ci/ci_cd_for_external_repos/_index.md)를 사용하여 미러링을 설정하면 이 설정이 기본적으로 활성화됩니다. 리포지토리 미러링을 수동으로 재구성하면 파이프라인 트리거가 기본적으로 꺼져 있으며 이것이 파이프라인이 실행을 멈추는 이유일 수 있습니다.
- [`rules`](../../../../ci/yaml/_index.md#rules) 구성이 파이프라인에 추가되는 작업을 방지합니다.
- 파이프라인은 [풀 미러를 설정한 계정](https://gitlab.com/gitlab-org/gitlab/-/issues/13697)을 사용하여 트리거됩니다. 계정이 더 이상 유효하지 않으면 파이프라인이 실행되지 않습니다.
- [브랜치 보호](../branches/protected.md#cicd-on-protected-branches)는 미러링을 설정한 계정이 파이프라인을 실행하는 것을 방지할 수 있습니다.

## `The repository is being updated`, 하지만 명확하게 실패하거나 성공하지 않음 {#the-repository-is-being-updated-but-neither-fails-nor-succeeds-visibly}

드물긴 하지만 Redis의 미러링 슬롯이 소진될 수 있으며, 메모리 부족(OoM) 이벤트로 인해 Sidekiq 워커가 회수되기 때문일 수 있습니다. 이 경우 미러링 작업이 시작되고 빠르게 완료되지만 실패하거나 성공하지도 않습니다. 또한 명확한 로그를 남기지 않습니다. 이 문제를 확인하려면:

1. [Rails 콘솔](../../../../administration/operations/rails_console.md)을 열고 Redis 미러링 용량을 확인합니다:

   ```ruby
   current = Gitlab::Redis::SharedState.with { |redis| redis.scard('MIRROR_PULL_CAPACITY') }.to_i
   maximum = Gitlab::CurrentSettings.mirror_max_capacity
   available = maximum - current
   ```

1. 미러링 용량이 `0`이거나 매우 낮으면 다음을 통해 모든 고정된 작업을 드레인할 수 있습니다:

   ```ruby
   Gitlab::Redis::SharedState.with { |redis| redis.smembers('MIRROR_PULL_CAPACITY') }.each do |pid|
     Gitlab::Redis::SharedState.with { |redis| redis.srem('MIRROR_PULL_CAPACITY', pid) }
   end
   ```

1. 명령을 실행한 후 [백그라운드 작업 페이지](../../../../administration/admin_area.md#background-jobs)에 새 미러링 작업이 예약되는 것이 표시되어야 하며, 특히 [수동으로 트리거](_index.md#update-a-mirror)될 때 그렇습니다.

## 잘못된 URL {#invalid-url}

[SSH](_index.md#ssh-authentication)를 통해 미러링을 설정하는 동안 이 오류가 나타나면 URL이 유효한 형식인지 확인합니다.

미러링은 `git@gitlab.com:gitlab-org/gitlab.git`의 형태인 SCP와 유사한 클론 URL을 지원하지 않으며, 호스트와 프로젝트 경로는 `:`로 구분됩니다. `ssh://` 프로토콜을 포함하는 [표준 URL](https://git-scm.com/docs/git-clone#_git_urls)이 필요하며, `ssh://git@gitlab.com/gitlab-org/gitlab.git`와 같습니다.

## 호스트 키 검증 실패 {#host-key-verification-failed}

이 오류는 대상 호스트 공개 SSH 키가 변경될 때 반환됩니다. 공개 SSH 키는 거의 변경되지 않습니다. 호스트 키 검증이 실패했지만 키가 여전히 유효하다고 의심되는 경우 리포지토리 미러를 삭제하고 다시 만들어야 합니다. 자세한 내용은 [리포지토리 미러 생성](_index.md#create-a-repository-mirror)을 참조하세요.

## 미러 사용자가 삭제되어 리포지토리 미러링 비활성화 {#repository-mirroring-disabled-because-mirror-user-was-deleted}

다음과 유사한 이메일 알림을 받을 수 있습니다:

```plaintext
Repository mirroring on <project_path> was disabled because the mirror user <username> was deleted.

To re-enable mirroring, update your repository mirroring settings.
```

이 문제는 각 미러가 이를 구성한 사용자에게 연결되어 있기 때문에 발생합니다. 해당 사용자의 계정이 삭제되면 GitLab에서 자동으로 미러를 비활성화합니다. 미러를 만드는 데 사용된 그룹 액세스 토큰 또는 프로젝트 액세스 토큰이 취소될 때도 같은 동작이 적용되는데, 이는 연결된 봇 사용자도 삭제되기 때문입니다.

미러를 다른 사용자에게 다시 할당할 수 없습니다. 이 문제를 해결하려면 다른 사용자로 미러를 다시 설정합니다.

자세한 내용은 [문제 488449](https://gitlab.com/gitlab-org/gitlab/-/work_items/488449)를 참조하세요.

## 미러 사용자 및 토큰을 단일 서비스 계정으로 전송 {#transfer-mirror-users-and-tokens-to-a-single-service-account}

이는 [GitLab Rails 콘솔](../../../../administration/operations/rails_console.md#starting-a-rails-console-session)에 대한 액세스가 필요합니다.

사용 사례: 여러 사용자가 자신의 GitHub 자격 증명을 사용하여 리포지토리 미러링을 설정하는 경우, 사람들이 회사를 떠날 때 미러링이 중단됩니다. 이 스크립트를 사용하여 분산된 미러링 사용자 및 토큰을 단일 서비스 계정으로 마이그레이션합니다:

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건 하에서 실행되지 않으면 손상을 야기할 수 있습니다. 항상 테스트 환경에서 먼저 명령을 실행하고 복원할 준비가 된 백업 인스턴스가 있어야 합니다.

```ruby
svc_user = User.find_by(username: 'ourServiceUser')
token = 'githubAccessToken'

Project.where(mirror: true).each do |project|
  import_url = project.unsafe_import_url

  # The expected url output is https://token@project/path.git
  repo_url = if import_url.include?('@')
               # Case 1: The url is something like https://23423432@project/path.git
               import_url.split('@').last
             elsif import_url.include?('//')
               # Case 2: The url is something like https://project/path.git
               import_url.split('//').last
             end

  next unless repo_url

  final_url = "https://#{token}@#{repo_url}"

  project.mirror_user = svc_user
  project.import_url = final_url
  project.username_only_import_url = final_url
  project.save
end
```

## `The requested URL returned error: 301` {#the-requested-url-returned-error-301}

`http://` 또는 `https://` 프로토콜을 사용하여 미러링할 때 리포지토리의 정확한 URL을 지정해야 합니다: `https://gitlab.example.com/group/project.git`

HTTP 리다이렉트는 따르지 않으며 `.git`을 생략하면 301 오류가 발생할 수 있습니다:

```plaintext
13:fetch remote: "fatal: unable to access 'https://gitlab.com/group/project': The requested URL returned error: 301\n": exit status 128.
```

## GitLab 인스턴스에서 Geo 보조로의 푸시 미러 실패 {#push-mirror-from-gitlab-instance-to-geo-secondary-fails}

HTTP 또는 HTTPS 프로토콜을 사용하는 GitLab 리포지토리의 푸시 미러링은 대상이 Geo 보조 노드이고 푸시 요청이 Geo 주 노드로 프록시되며 다음 오류가 표시될 때 실패합니다:

```plaintext
13:get remote references: create git ls-remote: exit status 128, stderr: "fatal: unable to access 'https://gitlab.example.com/group/destination.git/': The requested URL returned error: 302".
```

이는 Geo 통합 URL이 구성되어 있고 대상 호스트 이름이 보조 노드의 IP 주소로 확인될 때 발생합니다.

다음을 통해 오류를 방지할 수 있습니다:

- SSH 프로토콜을 사용하도록 푸시 미러를 구성합니다. 하지만 리포지토리에는 항상 HTTP 또는 HTTPS를 통해 전송되고 여전히 리다이렉트되는 LFS 객체가 포함되어 있지 않아야 합니다.
- 역 프록시를 사용하여 소스 인스턴스에서 주 Geo 노드로의 모든 요청을 전달합니다.
- 소스에 로컬 `hosts` 파일 항목을 추가하여 대상 호스트 이름이 Geo 주 노드의 IP 주소로 확인되도록 합니다.
- 대신 대상에서 풀 미러를 구성합니다.

## 풀 또는 푸시 미러를 업데이트하지 못함: `The project is not mirrored` {#pull-or-push-mirror-fails-to-update-the-project-is-not-mirrored}

[GitLab 자동 모드](../../../../administration/silent_mode/_index.md)가 활성화되면 풀 및 푸시 미러를 업데이트하지 못합니다. 이 경우 UI에서 미러링을 허용하는 옵션이 비활성화됩니다.

관리자는 GitLab 자동 모드가 비활성화되어 있는지 확인할 수 있습니다.

자동 모드로 인해 미러링이 실패할 때 다음은 디버그 단계입니다:

- [API를 사용하여 미러 트리거](pull.md#trigger-pipelines-for-mirror-updates)는 `The project is not mirrored`를 표시합니다.
- 풀 또는 푸시 미러가 이미 설정되었지만 미러링된 리포지토리에 추가 업데이트가 없는 경우 [프로젝트의 풀 및 푸시 미러 세부 정보 및 상태](../../../../api/project_pull_mirroring.md#retrieve-project-pull-mirror-details)가 아래 표시된 대로 최근이 아닌지 확인합니다. 이는 미러링이 일시 중지되었으며 GitLab 자동 모드를 비활성화하면 자동으로 다시 시작됨을 나타냅니다.

예를 들어, 자동 모드가 가져오기를 방해하는 경우 출력은 다음과 유사합니다:

```json
"id": 1,
"update_status": "finished",
"url": "https://test.git"
"last_error": null,
"last_update_at": null,
"last_update_started_at": "2023-12-12T00:01:02.222Z",
"last_successful_update_at": null
```

## 초기 미러링 실패: `Unable to pull mirror repo: Unable to get pack index` {#initial-mirroring-fails-unable-to-pull-mirror-repo-unable-to-get-pack-index}

다음과 유사한 오류가 나타날 수 있습니다:

```plaintext
13:fetch remote: "error: Unable to open local file /var/opt/gitlab/git-data/repositories/+gitaly/tmp/quarantine-[OMITTED].idx.temp.temp\nerror: Unable to get pack index https://git.example.org/ebtables/objects/pack/pack-[OMITTED].idx\nerror: Unable to find fcde2b2edba56bf408601fb721fe9b5c338d10ee under https://git.example.org/ebtables
Cannot obtain needed object fcde2b2edba56bf408601fb721fe9b5c338d10ee
while processing commit 2c26b46b68ffc68ff99b453c1d30413413422d70.
error: fetch failed.\n": exit status 128.
```

Gitaly가 "더미" HTTP 프로토콜을 통해 리포지토리 미러링 또는 가져오기를 지원하지 않기 때문에 이 문제가 발생합니다.

서버가 "스마트"인지 "더미"인지 확인하려면 cURL을 사용하여 `git-upload-pack` 서비스에 대한 참조 발견을 시작하고 Git "스마트" 클라이언트를 에뮬레이트합니다:

```shell
$GIT_URL="https://git.example.org/project"
curl --silent --dump-header - "$GIT_URL/info/refs?service=git-upload-pack"\
  -o /dev/null | grep -Ei "$content-type:"
```

- ["스마트" 서버](https://www.git-scm.com/docs/http-protocol#_smart_server_response)는 `application/x-git-upload-pack-advertisement`를 `Content-Type` 응답 헤더에 보고합니다.
- "더미" 서버는 `text/plain`를 `Content-Type` 응답 헤더에 보고합니다.

자세한 내용은 [참조 발견에 대한 Git 설명서](https://www.git-scm.com/docs/http-protocol#_discovering_references)를 참조하세요.

이를 해결하려면 다음 중 하나를 수행할 수 있습니다:

- 소스 리포지토리를 "스마트" 서버로 마이그레이션합니다.
- [SSH 프로토콜](_index.md#ssh-authentication)을 사용하여 리포지토리를 미러링합니다(인증 필요).

## 풀 미러링 실패: `Could not update main` {#pull-mirroring-fails-with-could-not-update-main}

다음과 유사한 오류가 나타날 수 있습니다:

- `9:Could not update main. Please refresh and try again.`

이는 대상 리포지토리가 완전히 비어 있지 않은 경우 초기 풀 미러 업데이트 중에 발생할 수 있습니다.

예를 들어, 대상 리포지토리에 다음이 이미 포함될 수 있습니다:

- 초기 README 커밋.
- 라이선스 또는 `.gitignore`.
- 기존 브랜치 또는 태그.

이 이슈를 해결하려면:

1. 대상 리포지토리를 빈 리포지토리로 다시 생성합니다.
1. 리포지토리가 소스 리포지토리와 동일한 개체 형식을 사용하는지 확인합니다.
1. README, 라이선스 또는 `.gitignore`로 리포지토리를 초기화하지 마세요.
1. 풀 미러링을 다시 구성하고 **지금 업데이트**를 실행합니다.

해결 방법으로, 기존 대상 리포지토리를 유지해야 하는 경우 **분기된 브랜치 덮어 쓰기**를 활성화하고 미러링 사용자가 대상 브랜치를 덮어쓸 수 있는 권한이 있는지 확인합니다.

## 오류: `mismatched algorithms` {#error-mismatched-algorithms}

다음과 유사한 오류가 나타날 수 있습니다:

```plaintext
13:fetch remote: "fatal: mismatched algorithms: client sha1; server sha256": exit status 128.
```

이 오류는 소스 및 대상 리포지토리가 다른 개체 형식을 사용하고 풀 미러링이 다른 개체 형식을 사용하는 리포지토리 간에 지원되지 않을 때 발생합니다.

예를 들어:

- 소스 리포지토리는 SHA-1을 사용합니다.
- 대상 리포지토리는 SHA-256을 사용하거나 그 반대입니다.

이 문제를 해결하려면 소스 리포지토리와 동일한 개체 형식으로 대상 리포지토리를 다시 생성한 다음 미러링을 다시 구성합니다.

## 오류: `File directory conflict` {#error-file-directory-conflict}

다음과 유사한 오류가 나타날 수 있습니다:

```plaintext
13:preparing reference update: file directory conflict
```

이 오류는 소스와 미러 리포지토리 간에 태그 또는 브랜치 이름 충돌이 있을 때 발생합니다. 예를 들어:

- `x/y`이라는 태그 또는 브랜치가 미러 리포지토리에 있습니다.
- `x`이라는 태그 또는 브랜치가 소스 리포지토리에 있습니다.

이 문제를 해결하려면 충돌하는 태그 또는 브랜치를 삭제합니다. 충돌하는 태그 또는 브랜치를 식별할 수 없으면 미러 리포지토리에서 모든 태그를 삭제합니다. 또 다른 옵션은 [분기된 브랜치를 덮어 쓰기](pull.md#overwrite-diverged-branches)하는 것입니다.

> [!note]
> 태그 삭제는 미러 리포지토리에서 수행된 모든 작업에 대해 파괴적일 수 있습니다.

미러 리포지토리에서 모든 태그를 삭제하고 제거하려면:

1. 미러링된 리포지토리의 로컬 복사본에서 다음을 실행합니다:

   ```shell
   git tag -l | xargs -n 1 git push --delete origin
   ```

1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **리포지토리 미러링**을 펼칩니다.
1. **지금 업데이트**({{< icon name="retry" >}})를 선택합니다.

## 대용량 LFS 파일로 미러링 중단 {#push-mirroring-stuck-with-large-lfs-files}

대용량 LFS 객체를 포함하는 프로젝트를 푸시 미러링할 때 시간 초과 문제가 발생할 수 있습니다. 이 문제는 Git LFS 작업이 기본 활동 시간 초과를 초과할 때 발생합니다. 이 오류는 미러링 로그에 나타납니다:

```plaintext
push to mirror: git push: exit status 1, stderr: "remote: GitLab: LFS objects are missing. Ensure LFS is properly set up or try a manual \"git lfs push --all\""
```

이 문제를 해결하려면 미러를 구성하기 전에 LFS 활동 시간 초과 값을 증가시킵니다:

```shell
git config lfs.activitytimeout 240
```

이 명령은 시간 초과를 `240` 초로 설정합니다. 파일 크기 및 네트워크 조건에 따라 이 값을 조정할 수 있습니다.
