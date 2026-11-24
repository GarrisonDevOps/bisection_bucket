---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 배포 키
description: "공용 SSH 키, 리포지토리 액세스, 봇 사용자 및 읽기 전용 액세스입니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

배포 키를 사용하여 GitLab에 호스팅된 리포지토리에 액세스합니다. 대부분의 경우 배포 키를 사용하여 빌드 서버 또는 CI(Continuous Integration) 서버 같은 외부 호스트에서 리포지토리에 액세스합니다.

필요에 따라 [배포 토큰](../deploy_tokens/_index.md)을 사용하여 리포지토리에 액세스할 수 있습니다.

| 속성        |  배포 키 | 배포 토큰 |
|------------------|-------------|--------------|
| 공유          | 여러 프로젝트 간에 공유 가능하며, 다른 그룹의 프로젝트도 포함됩니다. | 프로젝트 또는 그룹에 속합니다. |
| 소스           | 외부 호스트에서 생성된 공용 SSH 키입니다. | GitLab 인스턴스에서 생성되며, 생성 시에만 사용자에게 제공됩니다. |
| 액세스 가능한 리소스  | SSH 기반 Git 리포지토리 | HTTP 기반 Git 리포지토리, 패키지 레지스트리 및 컨테이너 레지스트리입니다. |

[외부 인증](../../../administration/settings/external_authorization.md)이 활성화된 경우 배포 키를 Git 작업에 사용할 수 없습니다.

## 범위 {#scope}

배포 키는 생성될 때 정의된 범위를 가집니다:

- **프로젝트 배포 키**: 액세스가 선택한 프로젝트로 제한됩니다.
- **공용 배포 키**: GitLab 인스턴스의 모든 프로젝트에 액세스를 부여할 수 있습니다. 각 프로젝트에 대한 액세스는 유지보수 관리자 역할 이상의 사용자가 [부여](#grant-project-access-to-a-public-deploy-key)해야 합니다.

배포 키를 생성한 후 범위를 변경할 수 없습니다.

## 권한 {#permissions}

배포 키는 생성될 때 권한 수준이 지정됩니다:

- **읽기 전용**: 읽기 전용 배포 키는 리포지토리에서만 읽을 수 있습니다.
- **읽기-쓰기**: 읽기-쓰기 배포 키는 리포지토리에서 읽고 쓸 수 있습니다.

배포 키를 생성한 후 권한 수준을 변경할 수 있습니다. 프로젝트 배포 키의 권한을 변경하면 현재 프로젝트에만 적용됩니다.

배포 키를 사용한 푸시로 추가 프로세스가 트리거되면 키의 생성자가 인증되어야 합니다. 예를 들어:

- 배포 키를 사용하여 커밋을 [보호된 브랜치](../repository/branches/protected.md)에 푸시하는 경우, 배포 키의 생성자는 해당 브랜치에 액세스할 수 있어야 합니다.
- 배포 키를 사용하여 CI/CD 파이프라인을 트리거하는 커밋을 푸시하는 경우, 배포 키의 생성자는 보호된 환경 및 비밀 변수를 포함한 CI/CD 리소스에 액세스할 수 있어야 합니다.

### 보안 영향 {#security-implications}

배포 키는 GitLab과의 비인간적 상호작용을 용이하게 하기 위한 것입니다. 예를 들어 배포 키를 사용하여 조직의 서버에서 자동으로 실행되는 스크립트에 권한을 부여할 수 있습니다.

[서비스 계정](../../profile/service_accounts.md)을 사용하고, 서비스 계정으로 배포 키를 생성해야 합니다. 다른 사용자 계정을 사용하여 배포 키를 생성하면, 배포 키가 취소될 때까지 유지되는 권한이 해당 사용자에게 부여됩니다.

또한:

- 배포 키 소유자가 차단되면 배포 키가 [거부](#deploy-key-is-rejected)됩니다. 풀과 푸시를 포함한 리포지토리 작업에 사용할 수 없습니다.
- 배포 키 소유자가 그룹 또는 프로젝트에서 제거되어도 배포 키는 거부되지 않습니다. 배포 키는 취소될 때까지 액세스를 제공하도록 계속됩니다.
- 배포 키가 보호된 브랜치 규칙에서 지정되면 배포 키의 생성자:
  - 보호된 브랜치 및 배포 키 자체에 액세스할 수 있습니다.
  - 배포 키에 읽기-쓰기 권한이 있으면 보호된 브랜치에 푸시할 수 있습니다. 이는 브랜치가 모든 사용자의 변경에 대해 보호되어 있어도 해당됩니다.

모든 민감한 정보와 마찬가지로 비밀에 액세스해야 하는 사람만 읽을 수 있도록 해야 합니다. 인간의 상호작용을 위해서는 개인 액세스 토큰과 같이 사용자와 연결된 자격증명을 사용하세요.

잠재적 비밀 유출을 탐지하는 데 도움이 되도록 [감사 이벤트](../../compliance/audit_event_schema.md#example-audit-event-payloads-for-git-over-ssh-events-with-deploy-key) 기능을 사용할 수 있습니다.

## 배포 키 보기 {#view-deploy-keys}

프로젝트에서 사용 가능한 배포 키를 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택하세요.
1. **키 배포**를 확장하세요.

사용 가능한 배포 키는 다음과 같이 나열됩니다:

- **활성화된 배포 키**: 프로젝트에 액세스할 수 있는 배포 키입니다.
- **비공개적으로 엑세스 가능한 배포키**: 프로젝트에 액세스할 수 없는 프로젝트 배포 키입니다.
- **공개적으로 엑세스 가능한 배포키**: 프로젝트에 액세스할 수 없는 공용 배포 키입니다.

[GitLab CLI](../../../editor_extensions/gitlab_cli/_index.md)는 `glab deploy-key list` 명령을 제공합니다.

## 프로젝트 배포 키 생성 {#create-a-project-deploy-key}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.
- [SSH 키 쌍을 생성하세요](../../ssh.md#generate-an-ssh-key-pair). 리포지토리에 액세스해야 하는 호스트에 개인 SSH 키를 배치하세요.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택하세요.
1. **키 배포**를 확장하세요.
1. **새 키 추가**를 선택하세요.
1. 필드를 완성하세요.
1. 선택 사항. `read-write` 권한을 부여하려면 **이 키에 쓰기 권한 부여** 확인란을 선택하세요.
1. 선택 사항. **만료일**을 업데이트하세요.

프로젝트 배포 키는 생성될 때 활성화됩니다. 프로젝트 배포 키의 이름과 권한만 수정할 수 있습니다. 배포 키가 여러 프로젝트에서 활성화된 경우 배포 키 이름을 수정할 수 없습니다.

[GitLab CLI](../../../editor_extensions/gitlab_cli/_index.md)는 `glab deploy-key add` 명령을 제공합니다.

## 공용 배포 키 생성 {#create-a-public-deploy-key}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

사전 요구 사항:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.
- [SSH 키 쌍을 생성](../../ssh.md#generate-an-ssh-key-pair)해야 합니다.
- 리포지토리에 액세스해야 하는 호스트에 개인 SSH 키를 배치해야 합니다.

공용 배포 키를 생성하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **키 배포**를 선택하세요.
1. **새 배포 키**를 선택하세요.
1. 필드를 완성하세요.
   - **이름**에 의미 있는 설명을 사용하세요. 예를 들어 공용 배포 키를 사용하는 외부 호스트 또는 애플리케이션의 이름을 포함하세요.

공용 배포 키의 이름만 수정할 수 있습니다.

## 공용 배포 키에 프로젝트 액세스 권한 부여 {#grant-project-access-to-a-public-deploy-key}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

공용 배포 키에 프로젝트 액세스를 부여하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택하세요.
1. **키 배포**를 확장하세요.
1. **공개적으로 엑세스 가능한 배포키**를 선택하세요.
1. 키의 행에서 **활성화**을 선택하세요.
1. 공용 배포 키에 읽기-쓰기 권한을 부여하려면:
   1. 키의 행에서 **편집** ({{< icon name="pencil" >}})을 선택하세요.
   1. **이 키에 쓰기 권한 부여** 확인란을 선택하세요.

### 배포 키의 프로젝트 액세스 권한 편집 {#edit-project-access-permissions-of-a-deploy-key}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

배포 키의 프로젝트 액세스 권한을 편집하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택하세요.
1. **키 배포**를 확장하세요.
1. 키의 행에서 **편집** ({{< icon name="pencil" >}})을 선택하세요.
1. **이 키에 쓰기 권한 부여** 확인란을 선택하거나 해제하세요.

## 배포 키의 프로젝트 액세스 권한 취소 {#revoke-project-access-of-a-deploy-key}

배포 키의 프로젝트 액세스를 취소하려면 이를 비활성화할 수 있습니다. 배포 키를 사용하는 모든 서비스는 키가 비활성화되면 작동을 중지합니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

배포 키를 비활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택하세요.
1. **키 배포**를 확장하세요.
1. **사용 안 함** ({{< icon name="cancel" >}})을 선택하세요.

배포 키가 비활성화되었을 때 발생하는 상황은 다음에 따라 달라집니다:

- 키가 공개적으로 액세스 가능한 경우 프로젝트에서 제거되지만 **공개적으로 엑세스 가능한 배포키** 탭에서는 여전히 사용할 수 있습니다.
- 키가 비공개적으로 액세스 가능하고 이 프로젝트에서만 사용 중인 경우 삭제됩니다.
- 키가 비공개적으로 액세스 가능하고 다른 프로젝트에서도 사용 중인 경우 프로젝트에서 제거되지만 **비공개적으로 엑세스 가능한 배포키** 탭에서는 여전히 사용할 수 있습니다.

## 관련 항목 {#related-topics}

- GitLab CLI [배포 키에 대한 명령](https://gitlab.com/gitlab-org/cli/-/tree/main/docs/source/deploy-key)

## 문제 해결 {#troubleshooting}

### 배포 키가 거부됨 {#deploy-key-is-rejected}

배포 키는 다음의 경우에 거부됩니다:

- 키 소유자가 차단됩니다.
- 키가 만료되었습니다.

배포 키가 거부되면 풀과 푸시를 포함한 모든 리포지토리 작업에 사용할 수 없습니다.

이 이슈를 해결하려면:

- 키 소유자가 차단된 경우 사용자를 차단 해제하거나 [키 소유자를 변경](#set-the-owner-of-a-deploy-key)하여 활성 사용자로 설정하세요.
- 키가 만료된 경우 새 배포 키를 생성하세요.

### 배포 키가 보호된 브랜치에 푸시할 수 없음 {#deploy-key-cannot-push-to-a-protected-branch}

배포 키가 [보호된 브랜치](../repository/branches/protected.md)에 푸시하지 못하는 몇 가지 시나리오가 있습니다.

- 배포 키와 연결된 소유자가 보호된 브랜치의 프로젝트에 대한 [멤버십](../members/_index.md)을 가지고 있지 않습니다.
- 배포 키와 연결된 소유자의 [프로젝트 멤버십 권한](../../permissions.md#project-permissions)이 **프로젝트 코드 보기**에 필요한 수준보다 낮습니다.
- 배포 키가 [프로젝트에 대한 읽기-쓰기 권한](#edit-project-access-permissions-of-a-deploy-key)을 가지고 있지 않습니다.
- 배포 키가 [취소](#revoke-project-access-of-a-deploy-key)되었습니다.
- **아무도 없음**이 보호된 브랜치의 [**푸시와 머지가 허용됨** 섹션](../repository/branches/protected.md#protect-a-branch)에서 선택됩니다.

모든 배포 키는 계정과 연결되어 있기 때문에 이 문제가 발생합니다. 계정의 권한이 변경될 수 있으므로 작동하던 배포 키가 갑자기 보호된 브랜치에 푸시할 수 없는 상황이 발생할 수 있습니다.

이 문제를 해결하려면 배포 키 API를 사용하여 자신의 사용자 대신 프로젝트 서비스 계정 사용자를 위한 배포 키를 생성할 수 있습니다:

1. [서비스 계정 사용자를 생성하세요](../../../api/service_accounts.md#create-a-group-service-account).
1. 해당 서비스 계정 사용자를 위해 [개인 액세스 토큰을 생성하세요](../../../api/service_accounts.md#create-a-personal-access-token-for-a-group-service-account). 이 토큰은 최소한 `api` 범위를 가져야 합니다.
1. [서비스 계정 사용자를 프로젝트에 초대하세요](../../profile/service_accounts.md#add-a-service-account-to-a-group-or-project).
1. 배포 키 API를 사용하여 [서비스 계정 사용자를 위한 배포 키를 생성](../../../api/deploy_keys.md#add-deploy-key)하세요:

   ```shell
   curl --request POST --header "PRIVATE-TOKEN: <service_account_access_token>" \
     --header "Content-Type: application/json" \
     --data '{"title": "My deploy key", "key": "ssh-rsa AAAA...", "can_push": "true"}' \
     --url "https://gitlab.example.com/api/v4/projects/5/deploy_keys/"
   ```

#### 비멤버 및 차단된 사용자와 연결된 배포 키 식별 {#identify-deploy-keys-associated-with-non-member-and-blocked-users}

비멤버 또는 차단된 사용자에게 속한 키를 찾아야 하는 경우 [Rails 콘솔](../../../administration/operations/rails_console.md#starting-a-rails-console-session)을 사용하여 다음과 유사한 스크립트를 사용하여 사용 불가능한 배포 키를 식별할 수 있습니다:

```ruby
DeployKeysProject.with_write_access.find_each do |deploy_key_mapping|
  project = deploy_key_mapping.project
  deploy_key = deploy_key_mapping.deploy_key
  user = deploy_key.user

  access_checker = Gitlab::DeployKeyAccess.new(deploy_key, container: project)

  # can_push_for_ref? tests if deploy_key can push to default branch, which is likely to be protected
  can_push = access_checker.can_do_action?(:push_code)
  can_push_to_default = access_checker.can_push_for_ref?(project.repository.root_ref)

  next if access_checker.allowed? && can_push && can_push_to_default

  if user.nil? || user.ghost?
    username = 'none'
    state = '-'
  else
    username = user.username
    user_state = user.state
  end

  puts "Deploy key: #{deploy_key.id}, Project: #{project.full_path}, Can push?: " + (can_push ? 'YES' : 'NO') +
       ", Can push to default branch #{project.repository.root_ref}?: " + (can_push_to_default ? 'YES' : 'NO') +
       ", User: #{username}, User state: #{user_state}"
end
```

#### 배포 키의 소유자 설정 {#set-the-owner-of-a-deploy-key}

배포 키는 특정 사용자에게 속하며 사용자가 차단되면 거부됩니다. 소유자가 차단되었을 때 배포 키가 계속 작동하도록 하려면 소유자를 활성 사용자로 변경하세요.

배포 키의 지문이 있는 경우 다음 명령을 사용하여 배포 키와 연결된 사용자를 변경할 수 있습니다:

```shell
k = Key.find_by(fingerprint: '5e:51:92:11:27:90:01:b5:83:c3:87:e3:38:82:47:2e')
k.user_id = User.find_by(username: 'anactiveuser').id
k.save()
```
