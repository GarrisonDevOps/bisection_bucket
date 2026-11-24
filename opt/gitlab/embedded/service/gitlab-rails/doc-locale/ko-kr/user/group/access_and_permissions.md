---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 그룹 액세스 및 권한을 구성하고 관리합니다.
title: 그룹 액세스 및 권한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹을 구성하여 그룹 권한 및 액세스를 제어합니다. 자세한 내용은 [프로젝트 및 그룹 공유](../project/members/sharing_projects_groups.md)도 참조하세요.

## Git 액세스 프로토콜 제한 {#restrict-git-access-protocols}

그룹의 리포지토리에 액세스하는 데 사용되는 허용된 프로토콜을 SSH, HTTPS 또는 둘 다로 설정할 수 있습니다. 이 설정은 관리자가 [인스턴스 설정](../../administration/settings/visibility_and_access_controls.md#configure-enabled-git-access-protocols)을 구성할 때 비활성화됩니다.

그룹의 허용된 Git 액세스 프로토콜을 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 확장합니다.
1. **활성화된 Git 액세스 프로토콜**에서 허용된 프로토콜을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## IP 주소로 그룹 액세스 제한 {#restrict-group-access-by-ip-address}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

조직의 사용자만 특정 리소스에 액세스할 수 있도록 IP 주소로 그룹에 대한 액세스를 제한할 수 있습니다. 이 최상위 그룹 설정은 다음에 적용됩니다:

- 부분군, 프로젝트 및 이슈를 포함한 GitLab UI입니다. GitLab Pages에는 적용되지 않습니다.
- API입니다.
- GitLab Self-Managed에서는 그룹에 대해 [전역적으로 허용된 IP 주소 범위](../../administration/settings/visibility_and_access_controls.md#configure-globally-allowed-ip-address-ranges)를 구성할 수도 있습니다.

관리자는 IP 주소로 제한된 액세스와 [전역적으로 허용된 IP 주소](../../administration/settings/visibility_and_access_controls.md#configure-globally-allowed-ip-address-ranges)를 결합할 수 있습니다.

> [!warning]
> IP 제한에는 `X-Forwarded-For` 헤더의 올바른 구성이 필요합니다. IP 스푸핑의 위험을 제한하려면 클라이언트가 보낸 `X-Forwarded-For` 헤더를 덮어써야 하며 추가하면 안 됩니다.
>
> 업스트림 프록시 또는 로드 밸런서가 없는 배포의 경우 사용자로부터 직접 요청을 수신하는 서버를 구성하여 원본 클라이언트 IP 주소를 보존하고 `X-Forwarded-For` 헤더를 덮어씁니다. 예를 들어 NGINX에서 구성 파일을 수정하여 다음을 포함하도록 합니다:
>
> ```plaintext
> proxy_set_header X-Forwarded-For $remote_addr;
> ```
>
> 업스트림 프록시 또는 로드 밸런서가 있는 배포의 경우 프록시 또는 로드 밸런서를 구성하여 원본 클라이언트 IP 주소를 보존하고 `X-Forwarded-For` 헤더를 덮어씁니다. 이 방식은 GitLab이 원본 클라이언트부터 시작하여 전체 IP 체인을 수신하고 IP 제한을 올바르게 평가할 수 있도록 합니다. 예를 들어 NGINX에서 구성 파일을 수정하여 다음을 포함하도록 합니다:
>
> ```plaintext
> proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
> ```

IP 주소로 그룹 액세스를 제한하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 확장합니다.
1. **IP 주소로 액세스 제한** 텍스트 상자에 CIDR 표기법의 IPv4 또는 IPv6 주소 범위 목록을 입력합니다:

   ```txt
   192.168.1.0/24
   10.0.0.0/8
   2001:db8::/32
   203.0.113.5/32
   ```

   각 IP 주소 항목을 수동으로 추가해야 합니다. 쉼표 또는 공백으로 구분된 여러 항목을 추가하는 것은 지원되지 않습니다. 대량 항목 지원은 [이슈 468998](https://gitlab.com/gitlab-org/gitlab/-/work_items/468998)에서 제안되었습니다.

   이 목록:
   - IP 주소 범위의 수에 제한이 없습니다.
   - SSH 또는 HTTP 권한이 부여된 IP 주소 범위 모두에 적용됩니다. 권한 부여 유형별로 이 목록을 분할할 수 없습니다.
1. **변경 사항 저장**을 선택합니다.

### 보안 영향 {#security-implications}

IP 액세스 제한은 그룹 및 프로젝트에 대한 액세스를 제한하지만 완전한 방화벽은 아닙니다. 이 기능은 일반적으로 그룹 및 프로젝트 리소스에 대한 액세스를 제한하지만 일부 정보는 제한된 사용자가 계속 액세스할 수 있습니다. 금지된 IP 주소에서 GitLab에 액세스할 때 다음 보안 영향(완전하지 않은) 목록을 염두에 두세요:

- 관리자 및 그룹 소유자는 항상 그룹 설정에 액세스할 수 있습니다.
- 관리자는 항상 그룹의 프로젝트에 액세스할 수 있습니다. 여기에는 코드 복제가 포함됩니다.
- 그룹 소유자는 항상 부분군에 액세스할 수 있지만 그룹이나 부분군의 모든 프로젝트에는 액세스할 수 없습니다.
- 사용자는 항상 공유 리소스에 액세스할 수 있습니다.
- 사용자는 항상 그룹 및 프로젝트의 이름과 계층을 볼 수 있습니다.
- 사용자는 항상 [이메일로 회신하기 기능](../../administration/reply_by_email.md)을 사용하여 이슈 또는 머지 리퀘스트에 대해 주석을 생성하고 편집할 수 있습니다.
- 사용자는 [수신 이메일 토큰](../../security/tokens/_index.md#incoming-email-token)으로 이메일을 통해 이슈 및 머지 리퀘스트를 생성할 수 있습니다. 수신 이메일은 IP 제한을 받지 않기 때문입니다.
- 사용자는 대시보드에서 푸시, 머지, 이슈 또는 주석 이벤트를 때때로 볼 수 있습니다.
- IP 제한은 항상 공개 프로젝트에 적용되지만 캐시된 프로젝트 파일은 때때로 액세스할 수 있습니다.
- IP 제한은 GitLab.com 및 GitLab Dedicated에서 SSH를 통한 Git 작업에 항상 적용됩니다. GitLab Self-Managed 인스턴스는 `gitlab-sshd`을 [PROXY 프로토콜](../../administration/operations/gitlab_sshd.md#proxy-protocol-support)이 활성화된 상태로 사용해야 합니다.
- IP 제한은 CI/CD 작업에서 수행하는 Git 복제 작업에 항상 적용됩니다.
- IP 제한은 러너 등록 또는 러너가 CI/CD 작업을 요청하거나 업데이트할 때 적용되지 않습니다.
- IP 제한은 포크된 프로젝트 또는 IP 제한 그룹의 이슈 또는 아티팩트와 간접적으로 상호 작용하는 작업에 적용되지 않을 수 있습니다. 예를 들어 머지 리퀘스트 설명의 이슈 참조를 사용하여 IP 제한 그룹의 이슈를 종료하는 머지 리퀘스트가 있습니다.
- IP 제한은 프로젝트 및 그룹 액세스 토큰, 서비스 계정, 배포 키 및 배포 토큰에 적용됩니다.

### GitLab.com 액세스 제한 {#gitlabcom-access-restrictions}

IP 주소 기반 그룹 액세스 제한은 [GitLab.com용 호스트된 러너](../../ci/runners/hosted_runners/_index.md)에서 작동하지 않습니다. 이러한 러너는 [동적 IP 주소](../gitlab_com/_index.md#ip-range)를 사용하는 임시 가상 머신으로 작동합니다(AWS, Google Cloud의 대규모 클라우드 공급자 풀에서). 이러한 광범위한 IP 범위를 허용하면 IP 주소 기반 액세스 제한의 목적이 무효화됩니다.

## 도메인으로 그룹 액세스 제한 {#restrict-group-access-by-domain}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

최상위 네임스페이스에서 이메일 도메인 허용 목록을 정의하여 사용자가 그룹 및 해당 프로젝트에 액세스할 수 있는 사용자를 제한할 수 있습니다. 사용자의 기본 이메일 도메인이 해당 그룹에 액세스하기 위해 허용 목록의 항목과 일치해야 합니다. 부분군은 동일한 허용 목록을 상속합니다.

도메인으로 그룹 액세스를 제한하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 확장합니다.
1. **이메일 도메인으로 회원가입 제한** 텍스트 상자에 허용할 도메인 이름을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

다음에 그룹에 사용자를 추가하려고 할 때 해당 사용자의 [기본 이메일](../profile/_index.md#change-your-primary-email)이 허용된 도메인 중 하나와 일치해야 합니다.

다음과 같은 가장 인기 있는 공개 이메일 도메인을 사용하여 제한할 수 없습니다:

- `aol.com`, `gmail.com`, `hotmail.co.uk`, `hotmail.com`,
- `hotmail.fr`, `icloud.com`, `live.com`, `mail.com`,
- `me.com`, `msn.com`, `outlook.com`,
- `proton.me`, `protonmail.com`, `tutanota.com`,
- `yahoo.com`, `yandex.com`, `zohomail.com`

그룹을 공유할 때 원본 및 대상 네임스페이스 모두 멤버의 이메일 주소 도메인을 허용해야 합니다.

> [!note]
> **이메일 도메인으로 회원가입 제한** 목록에서 도메인을 제거해도 해당 도메인을 가진 기존 사용자는 그룹 또는 해당 프로젝트에서 제거되지 않습니다. 또한 그룹 또는 프로젝트를 다른 그룹과 공유하면 대상 그룹은 원본 그룹 목록에 없는 더 많은 이메일 도메인을 목록에 추가할 수 있습니다. 따라서 이 기능은 현재 멤버가 항상 **이메일 도메인으로 회원가입 제한** 목록을 준수하도록 보장하지 않습니다.

## 사용자가 그룹에 대한 액세스를 요청하는 것을 방지 {#prevent-users-from-requesting-access-to-a-group}

그룹 소유자는 비멤버가 그룹에 액세스를 요청하는 것을 방지할 수 있습니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 확장합니다.
1. **사용자가 액세스를 요청하도록 허용** 확인란을 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

> [!note]
> **사용자가 액세스를 요청하도록 허용** 설정을 비활성화하면 새로운 액세스 요청이 방지됩니다. 기존 보류 중인 요청은 제거되지 않으며 여전히 승인하거나 거부할 수 있습니다.

## 그룹 외부에서 프로젝트 포크 방지 {#prevent-project-forking-outside-group}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

기본적으로 그룹의 프로젝트는 포크할 수 있습니다. 그러나 현재 최상위 그룹 외부에서 포크되는 것을 방지할 수 있습니다.

> [!note]
> 악의적 행위자의 잠재적 경로를 줄이기 위해 가능할 때 최상위 그룹 외부에서 포크하는 것을 방지하세요. 그러나 많은 외부 협업을 예상하는 경우 최상위 그룹 외부에서 포크를 허용하는 것이 불가피할 수 있습니다.

사전 요구 사항:

- 이 설정은 최상위 그룹에서만 활성화됩니다.
- 모든 부분군은 최상위 그룹에서 이 설정을 상속하며 부분군 수준에서 변경할 수 없습니다.

그룹 외부에서 프로젝트가 포크되는 것을 방지하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 확장합니다.
1. **현재 그룹 외부에서 프로젝트 포크 방지**를 확인합니다.
1. **변경 사항 저장**을 선택합니다.

기존 포크는 제거되지 않습니다.

## 그룹의 프로젝트에 멤버 추가 방지 {#prevent-members-from-being-added-to-projects-in-a-group}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹 소유자는 그룹의 모든 프로젝트에 대한 새로운 프로젝트 멤버십을 방지하여 프로젝트 멤버십을 더 엄격하게 제어할 수 있습니다.

예를 들어 감사를 위해 그룹을 잠그려면 [감사 이벤트](../../administration/compliance/audit_event_reports.md)를 통해 감사 중에 프로젝트 멤버십을 수정할 수 없도록 보장할 수 있습니다.

그룹 멤버십 잠금이 활성화되면 그룹 소유자는 여전히:

- 그룹을 초대하거나 멤버를 그룹에 추가하여 **잠금된** 그룹의 프로젝트에 액세스 권한을 부여합니다.
- 그룹 멤버의 역할을 변경합니다.

설정이 계단식으로 전파되지 않습니다. 부분군의 프로젝트는 부분군 구성을 따르며 상위 그룹을 무시합니다.

그룹의 프로젝트에 멤버가 추가되는 것을 방지하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 확장합니다.
1. **멤버십** 아래에서 **이 그룹의 프로젝트에 사용자를 추가할 수 없습니다.**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

그룹에 대한 멤버십을 잠근 후:

- 이전에 권한이 있던 모든 사용자는 더 이상 그룹에 멤버를 추가할 수 없습니다.
- 프로젝트에 새 사용자를 추가하기 위한 API 요청은 불가능합니다.

## LDAP를 사용하여 그룹 멤버십 관리 {#manage-group-memberships-with-ldap}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

{{< history >}}

- 그룹에서 동기화된 사용자에 대한 사용자 지정 역할 지원이 GitLab 17.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/435229)되었습니다.

{{< /history >}}

그룹 동기화를 통해 LDAP 그룹을 GitLab 그룹으로 매핑할 수 있습니다. 이는 그룹별 사용자 관리를 더 효과적으로 제어할 수 있습니다. 그룹 동기화를 구성하려면 `group_base` **DN**(`'OU=Global Groups,OU=GitLab INT,DC=GitLab,DC=org'`)을 편집합니다. 이 **OU**에는 GitLab 그룹과 연결된 모든 그룹이 포함되어 있습니다.

CN 또는 필터를 사용하여 그룹 링크를 생성할 수 있습니다. 이러한 그룹 링크를 생성하려면 그룹의 **설정** > **LDAP 동기화** 페이지로 이동합니다. 링크를 구성한 후 사용자가 GitLab 그룹과 동기화되는 데 1시간 이상 걸릴 수 있습니다. 링크를 구성한 후:

그룹 소유자는 [멤버 역할 API](../../api/member_roles.md) 또는 [그룹 멤버 API](../../api/group_members.md#add-a-group-member)를 사용하여 LDAP 동기화가 그룹에 대해 활성화된 경우에도 서비스 계정 사용자를 그룹에 추가하거나 제거할 수 있습니다. 그룹 소유자는 비서비스 계정 사용자를 추가하거나 제거할 수 없습니다.

사용자가 동일한 GitLab 그룹에 대해 구성된 여러 LDAP 그룹에 속할 때 GitLab은 두 관련 역할 중 더 높은 역할을 할당합니다. 예를 들어:

- 사용자는 `Owner`과(와) `Dev` LDAP 그룹의 멤버입니다.
- GitLab 그룹이 이 두 LDAP 그룹으로 구성되어 있습니다.
- 그룹 동기화가 완료되면 사용자에게 `Owner` 역할이 부여됩니다(이는 두 LDAP 그룹 역할 중 더 높은 역할입니다).

사용자 지정 역할을 사용하면 역할의 기본 액세스 수준이 다를 때 동일한 논리가 적용됩니다. 예를 들어:

- 사용자가 `Developer`과(와) `Developer + admin_vulnerability` LDAP 그룹의 멤버인 경우
- 사용자에게 `Developer + admin_vulnerability`이 부여됩니다(이는 두 LDAP 그룹 역할 중 더 높은 역할입니다).

두 사용자 지정 역할이 동일한 기본 액세스 수준을 공유할 때 GitLab은 순위만으로는 더 높은 역할을 결정할 수 없습니다. 대신 가장 먼저 생성된 그룹 링크의 사용자 지정 역할이 우선합니다. 예를 들어:

- 사용자가 `Developer + admin_vulnerability`과(와) `Developer + admin_merge_request` LDAP 그룹의 멤버인 경우
- 두 역할은 `Developer` 기본 액세스 수준을 공유합니다.
- 사용자에게 가장 먼저 생성된 LDAP 그룹 링크가 부여됩니다.

LDAP 및 그룹 동기화의 관리에 대한 자세한 내용은 [주 LDAP 설명서](../../administration/auth/ldap/ldap_synchronization.md#group-sync)를 참조하세요.

> [!note]
> LDAP 그룹 동기화를 추가할 때 LDAP 사용자가 그룹 멤버이고 LDAP 그룹에 포함되지 않으면 그룹에서 제거됩니다.

[LDAP 그룹을 통해 프로젝트 액세스 관리](../project/working_with_projects.md#manage-project-access-through-ldap-groups)하는 해결 방법을 사용할 수 있습니다.

### CN으로 그룹 링크 생성 {#create-group-links-with-a-cn}

LDAP 그룹 CN으로 그룹 링크를 생성하려면:

<!-- vale gitlab_base.Spelling = NO -->

1. 링크의 **LDAP 서버**를 선택합니다.
1. **동기화 방법**으로 `LDAP Group cn`을 선택합니다.
1. **LDAP 그룹 cn** 필드에서 그룹의 CN을 입력하기 시작합니다. 구성된 `group_base`에서 일치하는 CN이 있는 드롭다운 목록이 있습니다. 이 목록에서 CN을 선택합니다.
1. **LDAP 액세스** 섹션에서 이 그룹에서 동기화된 사용자에 대해 [기본 역할](../permissions.md) 또는 [사용자 지정 역할](../custom_roles/_index.md)을 선택합니다.
1. **동기화 추가**를 선택합니다.

GitLab은 일치하는 LDAP 사용자에게 역할을 연결하기 시작합니다. 이 프로세스는 완료하는 데 1시간 이상 걸릴 수 있습니다.

<!-- vale gitlab_base.Spelling = YES -->

### 필터를 사용하여 그룹 링크 생성 {#create-group-links-with-a-filter}

LDAP 사용자 필터로 그룹 링크를 생성하려면:

1. 링크의 **LDAP 서버**를 선택합니다.
1. **동기화 방법**으로 `LDAP user filter`을 선택합니다.
1. **LDAP 사용자 필터** 상자에 필터를 입력합니다. [사용자 필터에 대한 설명서](../../administration/auth/ldap/_index.md#set-up-ldap-user-filter)를 따릅니다.
1. **LDAP 액세스** 섹션에서 이 그룹에서 동기화된 사용자에 대해 [기본 역할](../permissions.md) 또는 [사용자 지정 역할](../custom_roles/_index.md)을 선택합니다.
1. **동기화 추가**를 선택합니다.

GitLab은 일치하는 LDAP 사용자에게 역할을 연결하기 시작합니다. 이 프로세스는 완료하는 데 1시간 이상 걸릴 수 있습니다.

### 그룹 링크 제거 {#remove-group-links}

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **활성 동기화**를 선택합니다.
1. 제거할 그룹 링크를 식별하고 **삭제**를 선택합니다.

> [!note]
> LDAP 그룹 동기화를 제거할 때 기존 멤버십 및 역할 할당이 유지됩니다. 그룹에 남은 LDAP 그룹 링크가 없으면 이러한 멤버십을 직접 편집할 수 있습니다. 먼저 재정의할 필요가 없습니다.

### 사용자 권한 재정의 {#override-user-permissions}

LDAP 사용자 권한을 관리자가 수동으로 재정의할 수 있습니다. 사용자의 권한을 재정의하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **관리** > **멤버**를 선택합니다. LDAP 동기화가 사용자에게 다음 역할을 부여한 경우:
   - 상위 그룹 멤버십보다 더 많은 권한이 있으면 해당 사용자는 그룹의 [직접 멤버십](../project/members/_index.md#display-direct-members)을 가지고 있는 것으로 표시됩니다.
   - 상위 그룹 멤버십과 동일하거나 더 적은 권한이 있으면 해당 사용자는 그룹의 [상속된 멤버십](../project/members/_index.md#membership-types)을 가지고 있는 것으로 표시됩니다.
1. 선택 사항. 편집하려는 사용자가 상속된 멤버십을 가지고 있는 것으로 표시되면 LDAP 사용자 권한을 재정의하기 전에 [부분군을 필터링하여 직접 멤버를 표시](_index.md#filter-a-group)합니다.
1. 편집 중인 사용자 행에서 연필({{< icon name="pencil" >}}) 아이콘을 선택합니다.
1. 대화 상자에서 **권한 수정**을 선택합니다.

이제 **멤버** 페이지에서 사용자의 권한을 편집할 수 있습니다.

## 파이프라인 변수를 사용할 수 있는 기본 역할 설정 {#set-the-default-role-that-can-use-pipeline-variables}

{{< history >}}

- GitLab 17.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/513117)되었습니다.

{{< /history >}}

이 그룹 설정은 [파이프라인 변수를 사용하여 새 파이프라인을 실행할 수 있는 최소 역할](../../ci/variables/_index.md#restrict-pipeline-variables) 프로젝트 설정의 기본값을 제어합니다. 그룹에서 생성된 새 프로젝트는 기본적으로 이 값이 선택된 상태입니다.

사전 요구 사항:

- 그룹에서 관리자 또는 소유자 역할이 있어야 합니다.
- 그룹은 부분군이 아닌 최상위 그룹이어야 합니다.

기본 최소 역할을 설정하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD** > **변수**를 선택합니다.
1. **파이프라인 변수를 사용하는 기본 역할** 아래에서 최소 역할을 선택하거나 **아무에게도 허락되지 않음**을 선택하여 사용자가 파이프라인 변수를 사용하는 것을 방지합니다.
1. **변경 사항 저장**을 선택합니다.

새 프로젝트를 생성한 후 관리자 또는 소유자 역할을 가진 프로젝트 멤버는 필요한 경우 프로젝트 설정을 다른 값으로 변경할 수 있습니다.

## MCP 서버에 대한 액세스 허용 {#allow-access-to-the-mcp-server}

{{< details >}}

- 제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- `mcp_server_availability_setting`라는 [기능 플래그](../../administration/feature_flags/_index.md)로 GitLab 19.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/230311)되었습니다. 기본적으로 사용 중지됩니다.
- GitLab 19.2에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/work_items/598279)입니다. 기능 플래그 `mcp_server_availability_setting`이 제거되었습니다.
- GitLab 19.2에서 GitLab Duo 기능이 있고 실험 및 베타 기능이 활성화된 기존 최상위 그룹에 대해 [활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241093)되었습니다.
- GitLab 19.5 이상에서 생성된 최상위 그룹에 대해 [기본적으로 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256761)되었습니다.

{{< /history >}}

이 설정이 그룹에 대해 활성화되어 있는지 여부는 그룹이 생성된 시기에 따라 달라집니다:

- 설정이 추가되었을 때 존재했던 그룹: GitLab Duo 기능과 실험 및 베타 기능이 모두 당시에 활성화되어 있었던 경우에만 활성화됩니다.
- 그 이후 GitLab 19.5까지 생성된 그룹: 기본적으로 비활성화됩니다.
- GitLab 19.5 이상에서 생성된 그룹: 기본적으로 활성화됩니다.

소유자는 모든 최상위 그룹에 대해 설정을 켜거나 끌 수 있습니다.

사전 요구 사항:

- 최상위 그룹의 소유자 역할이 있습니다.

최상위 그룹에 대한 MCP 서버 액세스를 변경하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **MCP 클라이언트 액세스** 섹션에서 **GitLab으로 연결을 허용** 확인란을 선택하거나 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

## 문제 해결 {#troubleshooting}

### IP 제한으로 액세스가 차단되었는지 확인 {#verify-if-access-is-blocked-by-ip-restriction}

사용자가 특정 그룹에 액세스하려고 할 때 404 오류가 표시되면 IP 제한에 의해 액세스가 차단될 수 있습니다.

`auth.log` rails 로그에서 다음 항목 중 하나 이상을 검색합니다:

- `json.message`: `'Attempting to access IP restricted group'`
- `json.allowed`: `false`

로그 항목을 보면서 `remote.ip`을 그룹의 [허용된 IP 주소](#restrict-group-access-by-ip-address) 목록과 비교합니다.

### 그룹 멤버에 대한 권한을 업데이트할 수 없음 {#cannot-update-permissions-for-a-group-member}

그룹 소유자가 그룹 멤버에 대한 권한을 업데이트할 수 없으면 어떤 멤버십이 나열되어 있는지 확인하세요. 그룹 소유자는 직접 멤버십만 업데이트할 수 있습니다.

부분군에 직접 추가된 멤버는 상위 그룹에서 동일하거나 더 높은 역할을 가지고 있으면 여전히 [상속된 멤버](../project/members/_index.md#membership-types)로 간주됩니다.

직접 멤버십을 보고 업데이트하려면 [그룹을 필터링하여 직접 멤버 표시](_index.md#filter-a-group)합니다.

[이슈 337539](https://gitlab.com/gitlab-org/gitlab/-/issues/337539#note_1277786161)는 직접 멤버십 및 간접 멤버십을 모두 나열하고 유형별로 필터링할 수 있는 기능을 가진 재설계된 멤버 페이지를 제안합니다.

### IP 제한 활성화 후 SSH를 사용하여 복제 또는 가져올 수 없음 {#cannot-clone-or-pull-using-ssh-after-enabling-ip-restrictions}

IP 주소 제한을 추가한 후 Git SSH 작업에 문제가 있으면 연결이 IPv6으로 기본 설정되는지 확인하세요.

일부 운영 체제는 둘 다 사용 가능할 때 IPv4보다 IPv6을 우선시하며, 이는 Git 터미널 피드백에서 명확하지 않을 수 있습니다.

연결에서 IPv6을 사용하는 경우 허용 목록에 IPv6 주소를 추가하여 이 문제를 해결할 수 있습니다.
