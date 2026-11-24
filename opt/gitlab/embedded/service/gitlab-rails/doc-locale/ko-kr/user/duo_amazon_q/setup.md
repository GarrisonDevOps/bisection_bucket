---
stage: AI Platform
group: AI Model Services
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: AWS 통합을 사용하여 GitLab Self-Managed 인스턴스에서 Amazon Q와 GitLab Duo를 설정하고 관리합니다.
title: Amazon Q와 GitLab Duo 설정
---

{{< details >}}

- 티어: Ultimate
- 추가 기능: Amazon Q와 GitLab Duo
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

{{< history >}}

- GitLab 17.7에서 [실험](../../policy/development_stages_support.md#experiment)으로 도입되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `amazon_q_integration`로 명명되었습니다. 기본적으로 비활성화되었습니다.
- `amazon_q_integration` 기능 플래그가 GitLab 17.8에서 제거되었습니다.
- GitLab 17.11에서 일반 공개되었습니다.

{{< /history >}}

> [!note]
> Amazon Q와 GitLab Duo는 다른 GitLab Duo 추가 기능과 결합할 수 없습니다.

Amazon Q와 GitLab Duo 구독을 받으려면 계정 담당자에게 문의하세요.

평가판을 요청하려면 [이 양식을 작성하세요](https://about.gitlab.com/partners/technology-partners/aws/#form).

GitLab Self-Managed에서 Amazon Q와 GitLab Duo를 설정하려면 다음 단계를 완료합니다.

## Amazon Q와 GitLab Duo 설정 {#set-up-gitlab-duo-with-amazon-q}

Amazon Q와 GitLab Duo를 설정하려면 다음을 수행해야 합니다:

- [필수 조건 완료](#prerequisites)
- [Amazon Q Developer 콘솔에서 프로필 생성](#create-a-profile-in-the-amazon-q-developer-console)
- [ID 공급자 생성](#create-an-iam-identity-provider)
- [IAM 역할 생성](#create-an-iam-role)
- [역할 편집](#edit-the-role)
- [GitLab에서 ARN 입력 및 Amazon Q 활성화](#enter-the-arn-in-gitlab-and-enable-amazon-q)
- [관리자가 고객 관리형 키를 사용하도록 허용](#allow-administrators-to-use-customer-managed-keys)

### 사전 요구 사항 {#prerequisites}

- GitLab Self-Managed가 있어야 합니다:
  - GitLab 17.11 이상입니다.
  - Amazon Q는 요청된 작업을 수행할 때 GitLab 인스턴스의 REST API를 사용하여 데이터를 읽고 쓰며 HTTPS URL에 액세스할 수 있어야 합니다([SSL 인증서는 자체 서명되지 않아야 합니다](https://docs.gitlab.com/omnibus/settings/ssl/)).
  - 인스턴스는 다음 IP 주소에서 시작된 Amazon Q 서비스의 인바운드 네트워크 액세스를 허용해야 하며 인스턴스가 구성된 포트에서 TCP/TLS를 사용합니다. 이는 [기본적으로 포트 443](../../administration/package_information/defaults.md#ports)입니다.
    - `34.228.181.128`
    - `44.219.176.187`
    - `54.226.244.221`
  - GitLab과 동기화된 Ultimate 구독 및 Amazon Q와 GitLab Duo 추가 기능이 있습니다.

### Amazon Q Developer 콘솔에서 프로필 생성 {#create-a-profile-in-the-amazon-q-developer-console}

Amazon Q Developer 프로필을 만듭니다.

1. [Amazon Q Developer 콘솔](https://us-east-1.console.aws.amazon.com/amazonq/developer/home#/gitlab)을 엽니다.
1. **Amazon Q Developer in GitLab**을 선택합니다.
1. **시작**을 선택합니다.
1. **프로필 이름**에 지역에 대한 고유한 프로필 이름을 입력합니다. 예를 들어, `QDevProfile-us-east-1`입니다.
1. 선택 사항. **프로필 설명 - 선택사항**에 설명을 입력합니다.
1. **생성**를 선택합니다.

### IAM ID 공급자 생성 {#create-an-iam-identity-provider}

IAM ID 공급자를 만듭니다. 먼저 GitLab에서 일부 값을 검색합니다.

사전 요구 사항:

- 관리자여야 합니다.

1. GitLab에 로그인합니다.
1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **Amazon Q와 GitLab Duo**를 확장합니다.
1. **구성 설정 보기**를 선택합니다.
1. 단계 1에서 공급자 URL과 오디언스를 복사합니다. 다음 단계에서 필요합니다.

이제 AWS ID 공급자를 생성합니다:

1. [AWS IAM 콘솔](https://console.aws.amazon.com/iam)에 로그인합니다.
1. **액세스 관리** > **ID 공급자**를 선택합니다.
1. **공급자 추가**를 선택합니다.
1. **공급자 유형**에 대해 **OpenID Connect**를 선택합니다.
1. **공급자 URL**에 GitLab의 값을 입력합니다.
1. **오디언스**에 GitLab의 값을 입력합니다.
1. **공급자 추가**를 선택합니다.

### IAM 역할 생성 {#create-an-iam-role}

다음으로 IAM ID 공급자를 신뢰하고 Amazon Q에 액세스할 수 있는 IAM 역할을 만들어야 합니다.

> [!note]
> IAM 역할을 설정한 후 역할과 연결된 AWS 계정을 변경할 수 없습니다.

1. AWS IAM 콘솔에서 **액세스 관리** > **역할** > **역할 생성**을 선택합니다.
1. **웹 ID**를 선택합니다.
1. **웹 ID**에 대해 이전에 입력한 공급자 URL을 선택합니다.
1. **오디언스**에 대해 이전에 입력한 오디언스 값을 선택합니다.
1. **다음**을 선택합니다.
1. **권한 추가** 페이지에서:
   - 관리되는 정책을 사용하려면 **권한 정책**에 대해 `GitLabDuoWithAmazonQPermissionsPolicy`을 검색하여 선택합니다.
   - 인라인 정책을 만들려면 **다음**을 선택하여 **권한 정책**을 건너뜁니다. 나중에 정책을 만듭니다.
1. **다음**을 선택합니다.
1. 역할의 이름을 지정합니다(예: `QDeveloperAccess`).
1. 신뢰 정책이 올바른지 확인합니다. 다음과 같아야 합니다:

   ```json
   {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {
                "Federated": "arn:aws:iam::<AWS_Account_ID>:oidc-provider/auth.token.gitlab.com/cc/oidc/<Instance_ID>"
            },
            "Condition": {
                "StringEquals": {
                    "auth.token.gitlab.com/cc/oidc/<Instance_ID>:aud": "gitlab-cc-<Instance_ID>"
                },

            }
         }
      ]
   }
   ```

1. **역할 생성**을 선택합니다.

### 인라인 정책 생성(선택사항) {#create-an-inline-policy-optional}

관리되는 정책을 사용하는 대신 인라인 정책을 만들려면:

1. **권한** > **권한 추가** > **인라인 정책 생성**을 선택합니다.
1. **JSON**을 선택하고 편집기에 다음을 붙여넣습니다:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "GitLabDuoUsagePermissions",
         "Effect": "Allow",
         "Action": [
           "q:SendEvent",
           "q:CreateAuthGrant",
           "q:UpdateAuthGrant",
           "q:GenerateCodeRecommendations",
           "q:SendMessage",
           "q:ListPlugins",
           "q:VerifyOAuthAppConnection"
         ],
         "Resource": "*"
       },
       {
         "Sid": "GitLabDuoManagementPermissions",
         "Effect": "Allow",
         "Action": [
           "q:CreateOAuthAppConnection",
           "q:DeleteOAuthAppConnection"
         ],
         "Resource": "*"
       },
       {
         "Sid": "GitLabDuoPluginPermissions",
         "Effect": "Allow",
         "Action": [
           "q:CreatePlugin",
           "q:DeletePlugin",
           "q:GetPlugin"
         ],
         "Resource": "arn:aws:qdeveloper:*:*:plugin/GitLabDuoWithAmazonQ/*"
       }
     ]
   }
   ```

1. **조치** > **가독성 최적화**를 선택하여 AWS에서 JSON을 형식화하고 분석하도록 합니다.
1. **다음**을 선택합니다.
1. 정책 이름을 `gitlab-duo-amazon-q-policy`로 지정하고 **정책 생성**을 선택합니다.

### 역할 편집 {#edit-the-role}

이제 역할을 편집합니다:

1. 방금 만든 역할을 찾아 선택합니다.
1. 세션 시간을 12시간으로 변경합니다. 세션이 12시간 이상으로 설정되지 않으면 `AssumeRoleWithWebIdentity`은 AI Gateway에서 실패합니다.

   1. **역할 검색** 필드에 IAM 역할의 이름을 입력한 다음 역할 이름을 선택합니다.
   1. **요약**에서 세션 기간을 편집하려면 **편집**을 선택합니다.
   1. **최대 세션 기간** 드롭다운 목록을 선택한 다음 **12시간**을 선택합니다.
   1. **변경사항 저장**을 선택합니다.

1. 페이지에 나열된 ARN을 복사합니다. 다음과 유사하게 표시됩니다:

   ```plaintext
   arn:aws:iam::123456789:role/QDeveloperAccess
   ```

### GitLab에서 ARN 입력 및 Amazon Q 활성화 {#enter-the-arn-in-gitlab-and-enable-amazon-q}

이제 ARN을 GitLab에 입력하고 기능에 액세스할 수 있는 그룹 및 프로젝트를 결정합니다.

사전 요구 사항:

- GitLab 관리자여야 합니다.

Amazon Q와 GitLab Duo 설정을 완료하려면:

1. GitLab에 로그인합니다.
1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **Amazon Q와 GitLab Duo**를 확장합니다.
1. **구성 설정 보기**를 선택합니다.
1. **IAM 역할의 ARN** 아래에 ARN을 붙여넣습니다.
1. Amazon Q와 GitLab Duo를 사용할 수 있는 그룹과 프로젝트를 결정하려면 옵션을 선택합니다:
   - 인스턴스에 대해 켜지만 그룹과 프로젝트가 끌 수 있도록 허용하려면 **기본적으로 켜짐**을 선택합니다.
     - 선택 사항. Amazon Q를 자동으로 병합 요청에서 코드를 검토하도록 구성하려면 **자동으로 병합 요청 내에 Amazon Q 리뷰 코드 생성**을 선택합니다.
   - 인스턴스에 대해 끄지만 그룹과 프로젝트가 켤 수 있도록 허용하려면 **기본적으로 꺼짐**을 선택합니다.
   - 인스턴스에 대해 끄고 그룹 또는 프로젝트가 켤 수 없도록 방지하려면 **항상 꺼짐**을 선택합니다.

1. **변경 사항 저장**을 선택합니다.

저장하면 API가 AI Gateway에 연결하여 Amazon Q에서 OAuth 애플리케이션을 만들어야 합니다.

성공했는지 확인하려면:

- Amazon CloudWatch 콘솔 로그에서 `204` 상태 코드를 확인합니다. 자세한 내용은 [Amazon CloudWatch란?](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html)을 참조하세요.
- GitLab에서 `Amazon Q settings have been saved`이(가) 표시되는 알림이 표시됩니다.
- GitLab의 왼쪽 사이드바에서 **응용 프로그램**을 선택합니다. Amazon Q OAuth 애플리케이션이 표시됩니다.

## 관리자가 고객 관리형 키를 사용하도록 허용 {#allow-administrators-to-use-customer-managed-keys}

관리자인 경우 AWS Key Management Service(AWS KMS) 고객 관리형 키(CMK)를 사용하여 고객 데이터를 암호화할 수 있습니다.

KMS 콘솔의 구성된 역할에서 키 정책을 만들 때 CMK를 사용할 수 있는 권한을 부여하도록 역할 정책을 업데이트합니다.

`kms:ViaService` 조건 키는 KMS 키의 사용을 지정된 AWS 서비스의 요청으로 제한합니다. 또한 특정 서비스에서 요청이 올 때 KMS 키를 사용할 수 있는 권한을 거부하는 데 사용됩니다. 조건 키를 사용하면 CMK를 사용하여 콘텐츠를 암호화하거나 해독할 수 있는 사용자를 제한할 수 있습니다.

```json
{
   "Version": "2012-10-17",
   "Statement": [
      {
         "Sid": "Sid0",
         "Effect": "Allow",
         "Principal": {
            "AWS": "arn:aws:iam::<awsAccountId>:role/<rolename>"
         },
         "Action": [
            "kms:Decrypt",
            "kms:DescribeKey",
            "kms:Encrypt",
            "kms:GenerateDataKey",
            "kms:GenerateDataKeyWithoutPlaintext",
            "kms:ReEncryptFrom",
            "kms:ReEncryptTo"
         ],
         "Resource": "*",
         "Condition": {
            "StringEquals": {
                "kms:ViaService": [
                    "q.<region>.amazonaws.com"
                ]
            }
        }
      }
   ]
}
```

자세한 내용은 [AWS KMS 개발자 가이드에서 `kms:ViaService`](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html#conditions-kms-via-service)을 참조하세요.

## AWS에서 호스팅하는 AI Gateway를 사용하도록 GitLab 구성 {#configure-gitlab-to-use-aws-hosted-ai-gateway}

AWS에서 호스팅하는 AI Gateway를 사용하도록 GitLab을 구성할 수 있습니다.

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건 하에서 실행되지 않으면 손상을 야기할 수 있습니다. 항상 테스트 환경에서 먼저 명령을 실행하고 복원할 준비가 된 백업 인스턴스가 있어야 합니다.

1. [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)을 시작합니다. 예를 들어 Linux 패키지를 사용하는 설치의 경우 다음을 실행합니다:

   ```shell
   sudo gitlab-rails console
   ```

1. 현재 할당된 서비스 URL을 보려면 다음을 실행합니다:

   ```ruby
   ApplicationSetting.current.ai_gateway_url
   ```

1. 서비스 URL을 업데이트하려면 다음을 실행합니다:

   ```ruby
   ApplicationSetting.current.update!(ai_gateway_url: "https://cloud.gitlab.com/aws/ai")
   ```

## Amazon Q와 GitLab Duo 끄기 {#turn-off-gitlab-duo-with-amazon-q}

인스턴스, 그룹 또는 프로젝트에 대해 Amazon Q와 GitLab Duo를 끌 수 있습니다.

### 인스턴스에 대해 끄기 {#turn-off-for-the-instance}

사전 요구 사항:

- 관리자여야 합니다.

인스턴스에 대해 Amazon Q와 GitLab Duo를 끄려면:

1. GitLab에 로그인합니다.
1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **Amazon Q와 GitLab Duo**를 확장합니다.
1. **구성 설정 보기**를 선택합니다.
1. **항상 꺼짐**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 그룹에 대해 끄기 {#turn-off-for-a-group}

사전 요구 사항:

- 그룹에 대해 소유자 역할이 있어야 합니다.

그룹에 대해 Amazon Q와 GitLab Duo를 끄려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **Amazon Q**를 확장합니다.
1. 옵션을 선택합니다:
   - 그룹에 대해 끄지만 다른 그룹이나 프로젝트가 켤 수 있도록 허용하려면 **기본적으로 꺼짐**을 선택합니다.
   - 그룹에 대해 끄고 다른 그룹이나 프로젝트가 켤 수 없도록 방지하려면 **항상 꺼짐**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 프로젝트에 대해 끄기 {#turn-off-for-a-project}

사전 요구 사항:

- 프로젝트에 대해 소유자 역할이 있어야 합니다.

프로젝트에 대해 Amazon Q와 GitLab Duo를 끄려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한**을 확장합니다.
1. **Amazon Q** 아래에서 토글을 끕니다.
1. **변경 사항 저장**을 선택합니다.

## 문제 해결 {#troubleshooting}

GitLab을 Amazon Q에 연결하는 데 문제가 발생하면 GitLab 설치가 [모든 필수 조건](#prerequisites)을 충족하는지 확인합니다.

다음 문제가 발생할 수도 있습니다.

### GitLab 인스턴스 UUID 불일치 {#gitlab-instance-uuid-mismatch}

Amazon Q에서 연결을 끊을 때 `GitLab instance UUID mismatch` 오류가 발생하거나 상태 확인을 실행할 때 `Cannot obtain OIDC token` 오류가 발생할 수 있습니다. 예를 들어:

```plaintext
Authentication with the AI gateway services failed: AI Gateway returned code 500: {"detail":"Cannot obtain OIDC token"}
Amazon Q connectivity check failed: Cannot obtain OIDC token
```

이러한 오류는 일반적으로 다음과 같은 경우에 발생합니다:

- GitLab 인스턴스가 백업에서 복원되었습니다.
- GitLab 인스턴스가 새 인프라로 마이그레이션되었습니다.
- GitLab 인스턴스 UUID가 다른 이유로 변경되었습니다.

UUID 불일치가 근본 원인임을 확인하려면 다음 검증 단계를 진행합니다.

#### 검증 {#validate}

1. GitLab이 호스팅되는 EC2 인스턴스에 로그인합니다.
1. Rails 콘솔에 액세스합니다.
1. 현재 UUID 가져오기: `Gitlab::CurrentSettings.current_application_settings.uuid`
1. JWT 토큰을 가져옵니다:

   ```ruby
   token = CloudConnector::Tokens.get(unit_primitive: :agent_quick_actions, resource: :instance)
   JWT.decode(token, false, nil)
   ```

UUID의 불일치가 `sub` 필드(단계 3)와 단계 4의 `gitlab_instance_uuid` 사이에 존재할 때 문제가 명백합니다.

이 문제를 해결하려면 다음 단계를 완료합니다.

1. 모든 활성 라이선스를 제거합니다.
1. 모든 구독 추가 기능 구매를 삭제합니다:

   Rails 콘솔을 열고 다음을 실행합니다:

   ```ruby
   GitlabSubscriptions::AddOnPurchase.all.destroy_all
   ```

1. 인스턴스 UUID 재설정을 실행합니다. Rails 콘솔에서 다음을 실행합니다:

   ```ruby
   ApplicationSetting.update!(uuid: SecureRandom.uuid)
   ```

1. 활성 라이선스를 적용합니다.
1. 잠시 기다렸다가 라이선스를 동기화합니다. 이 작업은 클라우드 커넥터 토큰이 재생성되도록 합니다. (이 단계 없이 헤더 불일치가 발생합니다.)
1. IdP 및 IAM 역할을 새 UUID로 업데이트합니다.
1. 다음 단계를 선택합니다:
   - 기존 IdP 및 IAM 역할을 새 UUID로 업데이트하고 Amazon Q와 GitLab Duo를 계속 사용하여 기존 설정을 계속 사용합니다.
   - 오프보드:
     1. Amazon Q와 GitLab Duo에서 오프보드합니다.
     1. 원하는 경우 새로운 연결을 설정합니다.

완료되면 UUID 불일치 문제가 해결되고 Amazon Q와 GitLab Duo가 새 구성으로 제대로 작동해야 합니다.
